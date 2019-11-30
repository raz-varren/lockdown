package main

type Stats struct {
	SkipCount int64
	SkipFiles []string

	DelCount int64
	DelFiles []string

	MkCount int64
	MkFiles []string

	ErrCount int64
	ErrFiles []string
}

func (s *Stats) TotalFiles() int64 {
	return s.SkipCount + s.MkCount + s.ErrCount
}

func (s *Stats) AllFiles() []string {
	fList := []string{}

	for _, f := range s.SkipFiles {
		fList = append(fList, f)
	}

	for _, f := range s.DelFiles {
		fList = append(fList, f)
	}

	for _, f := range s.MkFiles {
		fList = append(fList, f)
	}

	for _, f := range s.ErrFiles {
		fList = append(fList, f)
	}

	return fList
}

func (s *Stats) AddSkip(f string) {
	s.SkipCount++
	s.SkipFiles = append(s.SkipFiles, f)
}

func (s *Stats) AddDel(f string) {
	s.DelCount++
	s.DelFiles = append(s.DelFiles, f)
}

func (s *Stats) AddMk(f string) {
	s.MkCount++
	s.MkFiles = append(s.MkFiles, f)
}

func (s *Stats) AddErr(f string) {
	s.ErrCount++
	s.ErrFiles = append(s.ErrFiles, f)
}

func NewStats() *Stats {
	return &Stats{
		SkipFiles: []string{},
		DelFiles:  []string{},
		MkFiles:   []string{},
		ErrFiles:  []string{},
	}
}
