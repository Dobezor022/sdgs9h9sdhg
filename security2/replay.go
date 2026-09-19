package security2

type ReplayWindow struct {
	Highest uint64 `json:"highest"`
	Bitmap  uint64 `json:"bitmap"`
}

func (w *ReplayWindow) Accept(sequence uint64) error {
	if w == nil {
		return ErrInvalidInput
	}
	if sequence > w.Highest {
		shift := sequence - w.Highest
		if shift >= 64 {
			w.Bitmap = 1
		} else {
			w.Bitmap = (w.Bitmap << shift) | 1
		}
		w.Highest = sequence
		return nil
	}
	delta := w.Highest - sequence
	if delta >= 64 {
		return ErrReplay
	}
	mask := uint64(1) << delta
	if w.Bitmap&mask != 0 {
		return ErrReplay
	}
	w.Bitmap |= mask
	return nil
}
