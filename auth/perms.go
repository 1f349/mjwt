package auth

import (
	"bufio"
	"encoding/json"
	"github.com/becheran/wildmatch-go"
	"gopkg.in/yaml.v3"
	"sort"
	"strings"
)

type PermStorage struct {
	values map[string]struct{}
}

func NewPermStorage() *PermStorage {
	return new(PermStorage).setup()
}

func ParsePermStorage(perms string) *PermStorage {
	ps := NewPermStorage()
	sc := bufio.NewScanner(strings.NewReader(perms))
	sc.Split(bufio.ScanWords)
	for sc.Scan() {
		ps.Set(sc.Text())
	}
	return ps
}

func (p *PermStorage) setup() *PermStorage {
	if p.values == nil {
		p.values = make(map[string]struct{})
	}
	return p
}

func (p *PermStorage) Set(perm string) {
	p.values[perm] = struct{}{}
}

func (p *PermStorage) Clear(perm string) {
	delete(p.values, perm)
}

func (p *PermStorage) Has(perm string) bool {
	_, ok := p.values[perm]
	return ok
}

func (p *PermStorage) OneOf(o *PermStorage) bool {
	for i := range o.values {
		if p.Has(i) {
			return true
		}
	}
	return false
}

func (p *PermStorage) Dump() []string {
	a := make([]string, 0, len(p.values))
	for i := range p.values {
		a = append(a, i)
	}
	sort.Strings(a)
	return a
}

func (p *PermStorage) Search(v string) []string {
	m := wildmatch.NewWildMatch(v)
	var a []string
	for i := range p.values {
		if m.IsMatch(i) {
			a = append(a, i)
		}
	}
	return a
}

func (p *PermStorage) Filter(match []string) *PermStorage {
	out := NewPermStorage()
	for _, i := range match {
		for _, j := range p.Search(i) {
			out.Set(j)
		}
	}
	return out
}

func (p *PermStorage) prepare(a []string) {
	for _, i := range a {
		p.Set(i)
	}
}

func (p *PermStorage) MarshalJSON() ([]byte, error) { return json.Marshal(p.Dump()) }

func (p *PermStorage) UnmarshalJSON(bytes []byte) error {
	p.setup()
	var a []string
	err := json.Unmarshal(bytes, &a)
	if err != nil {
		return err
	}
	p.prepare(a)
	return nil
}

func (p *PermStorage) MarshalYAML() (interface{}, error) { return yaml.Marshal(p.Dump()) }

func (p *PermStorage) UnmarshalYAML(value *yaml.Node) error {
	p.setup()
	var a []string
	err := value.Decode(&a)
	if err != nil {
		return err
	}
	p.prepare(a)
	return nil
}
