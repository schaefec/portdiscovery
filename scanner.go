package scanner

struct type Scanner {
	WaitGroup *sync.WaitGroup
}

func New(wg *sync.WaitGroup) (*Scanner) {
	return &Scanner{
		WaitGroup: wg
	}
}

