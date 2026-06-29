package alg_ecdsa

import (
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	refreshpkg "github.com/getamis/alice/crypto/tss/ecdsa/cggmp/refresh"
	"github.com/godaddy-x/wallet-mpc-node/mpc"
)

const (
	// SignMaterialWarmThreshold 触发后台 refresh（QPS=10 时缓冲约 (64-40)/10=2.4s+）。
	SignMaterialWarmThreshold = 40
	// SignMaterialWarnThreshold 告警级使用次数。
	SignMaterialWarnThreshold = 56
	// SignMaterialSyncWaitUses 第 64 次签名后触发 App 同步等待 warm（降级层）。
	SignMaterialSyncWaitUses = 64
	// SignMaterialMaxUses 硬上限：已完成 64 次签名后拒绝（uses>=64 时不可再 Acquire）。
	SignMaterialMaxUses = 64
	// SignMaterialTTL refresh 材料最长有效时间。
	SignMaterialTTL = 10 * time.Minute
)

// ErrSignMaterialNotReady 在线签名路径无可用 refresh 材料。
var ErrSignMaterialNotReady = errors.New("ecdsa: sign material not ready")

// ErrSignMaterialExhausted 材料已超过硬上限（uses>64）。
var ErrSignMaterialExhausted = errors.New("ecdsa: sign material exhausted")

// MaterialAcquireResult Acquire 返回值。
type MaterialAcquireResult struct {
	Result    *refreshpkg.Result
	NeedWarm  bool
	UseCount  int
	Tier      MaterialUseTier
}

type signMaterialSlot struct {
	result    *refreshpkg.Result
	uses      int
	createdAt time.Time
}

type signMaterialBuffer struct {
	mu          sync.Mutex
	active      atomic.Pointer[signMaterialSlot]
	warmPending bool
	maxUses     int
	warmAt      int
	ttl         time.Duration
}

// SignMaterialPool 节点本地材料池。
type SignMaterialPool struct {
	mu      sync.Mutex
	buffers map[string]*signMaterialBuffer
}

var DefaultSignMaterialPool = NewSignMaterialPool()

func NewSignMaterialPool() *SignMaterialPool {
	return &SignMaterialPool{
		buffers: make(map[string]*signMaterialBuffer),
	}
}

func (p *SignMaterialPool) buffer(materialKey string) *signMaterialBuffer {
	p.mu.Lock()
	defer p.mu.Unlock()
	b, ok := p.buffers[materialKey]
	if !ok {
		b = &signMaterialBuffer{
			maxUses: SignMaterialMaxUses,
			warmAt:  SignMaterialWarmThreshold,
			ttl:     SignMaterialTTL,
		}
		p.buffers[materialKey] = b
	}
	return b
}

func (b *signMaterialBuffer) loadActive() *signMaterialSlot {
	return b.active.Load()
}

func (b *signMaterialBuffer) slotValid(s *signMaterialSlot) bool {
	if s == nil || s.result == nil {
		return false
	}
	if b.ttl > 0 && time.Since(s.createdAt) > b.ttl {
		return false
	}
	// uses==64 表示已完成 64 次签名，不可再取。
	if s.uses >= b.maxUses {
		return false
	}
	return true
}

// MaterialSessionKey 节点本地材料池键；participants 顺序无关（内部 SortedNodeIDs 规范化）。
func MaterialSessionKey(keyID, selfNodeID string, participants []string) string {
	return RefreshSessionKey(keyID, mpc.SortedNodeIDs(participants)) + "|" + selfNodeID
}

// Acquire 在线 sign 取材料；uses 递增后返回分级。
func (p *SignMaterialPool) Acquire(materialKey string) (*MaterialAcquireResult, error) {
	b := p.buffer(materialKey)
	b.mu.Lock()
	defer b.mu.Unlock()

	active := b.loadActive()
	if !b.slotValid(active) {
		if active != nil && active.uses >= b.maxUses {
			return nil, fmt.Errorf("%w (key=%s uses=%d)", ErrSignMaterialExhausted, materialKey, active.uses)
		}
		return nil, fmt.Errorf("%w (key=%s)", ErrSignMaterialNotReady, materialKey)
	}
	cloned, err := cloneRefreshResult(active.result)
	if err != nil {
		return nil, err
	}
	active.uses++
	useCount := active.uses
	needWarm := useCount >= b.warmAt && !b.warmPending
	if needWarm {
		b.warmPending = true
	}
	b.active.Store(active)
	return &MaterialAcquireResult{
		Result:   cloned,
		NeedWarm: needWarm,
		UseCount: useCount,
		Tier:     MaterialUseTierForCount(useCount),
	}, nil
}

// CommitWarm 原子替换 active；旧秘密材料显式清零。
func (p *SignMaterialPool) CommitWarm(materialKey string, result *refreshpkg.Result) error {
	if result == nil {
		return fmt.Errorf("ecdsa: nil warm refresh result")
	}
	cloned, err := cloneRefreshResult(result)
	if err != nil {
		return err
	}
	b := p.buffer(materialKey)
	b.mu.Lock()
	defer b.mu.Unlock()

	if old := b.loadActive(); old != nil {
		zeroRefreshResult(old.result)
	}
	b.active.Store(&signMaterialSlot{
		result:    cloned,
		uses:      0,
		createdAt: time.Now(),
	})
	b.warmPending = false
	invalidatePresignPoolForMaterial(materialKey)
	return nil
}

// invalidatePresignPoolForMaterial Refresh 替换后作废关联 Pre-Sign 池（当前未实现 Pre-Sign，预留钩子）。
func invalidatePresignPoolForMaterial(materialKey string) {
	_ = materialKey
}

// MarkWarmFailed warm 失败时释放 pending。
func (p *SignMaterialPool) MarkWarmFailed(materialKey string) {
	b := p.buffer(materialKey)
	b.mu.Lock()
	defer b.mu.Unlock()
	b.warmPending = false
}

// HasReady 是否已有可签名材料。
func (p *SignMaterialPool) HasReady(materialKey string) bool {
	b := p.buffer(materialKey)
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.slotValid(b.loadActive())
}

// Clear 测试或 key 轮换时清空。
func (p *SignMaterialPool) Clear() {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, b := range p.buffers {
		if old := b.loadActive(); old != nil {
			zeroRefreshResult(old.result)
		}
	}
	p.buffers = make(map[string]*signMaterialBuffer)
}

func ClearSignMaterialPool() {
	DefaultSignMaterialPool.Clear()
}
