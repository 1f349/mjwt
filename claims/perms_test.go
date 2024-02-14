package claims

import (
	"bytes"
	"github.com/stretchr/testify/assert"
	"sort"
	"testing"
)

func TestParsePermStorage(t *testing.T) {
	t.Parallel()
	ps := ParsePermStorage("mjwt:test mjwt:test2")
	if _, ok := ps.values["mjwt:test"]; !ok {
		assert.Fail(t, "perm not set")
	}
}

func TestPermStorage_Set(t *testing.T) {
	t.Parallel()
	ps := NewPermStorage()
	ps.Set("mjwt:test")
	if _, ok := ps.values["mjwt:test"]; !ok {
		assert.Fail(t, "perm not set")
	}
}

func TestPermStorage_Clear(t *testing.T) {
	t.Parallel()
	ps := NewPermStorage()
	ps.values["mjwt:test"] = struct{}{}
	ps.Clear("mjwt:test")
	if _, ok := ps.values["mjwt:test"]; ok {
		assert.Fail(t, "perm not cleared")
	}
}

func TestPermStorage_Has(t *testing.T) {
	t.Parallel()
	ps := NewPermStorage()
	assert.False(t, ps.Has("mjwt:test"))
	ps.values["mjwt:test"] = struct{}{}
	assert.True(t, ps.Has("mjwt:test"))
}

func TestPermStorage_OneOf(t *testing.T) {
	t.Parallel()
	o := NewPermStorage()
	o.Set("mjwt:test")
	o.Set("mjwt:test2")

	ps := NewPermStorage()
	assert.False(t, ps.OneOf(o))
	ps.values["mjwt:test"] = struct{}{}
	assert.True(t, ps.OneOf(o))
	ps.values["mjwt:test2"] = struct{}{}
	assert.True(t, ps.OneOf(o))
	delete(ps.values, "mjwt:test")
	assert.True(t, ps.OneOf(o))
	delete(ps.values, "mjwt:test2")
	assert.False(t, ps.OneOf(o))
}

func TestPermStorage_Search(t *testing.T) {
	ps := ParsePermStorage("mjwt:test mjwt:test2 mjwt:other")
	a := ps.Search("mjwt:test*")
	sort.Strings(a)
	assert.Equal(t, []string{"mjwt:test", "mjwt:test2"}, a)
	assert.Equal(t, []string{"mjwt:other"}, ps.Search("mjwt:other"))
}

func TestPermStorage_Filter(t *testing.T) {
	ps := ParsePermStorage("mjwt:test mjwt:test2 mjwt:other mjwt:other2 mjwt:another")
	a := ps.Filter([]string{"mjwt:test*", "mjwt:other*"}).Dump()
	sort.Strings(a)
	assert.Equal(t, []string{"mjwt:other", "mjwt:other2", "mjwt:test", "mjwt:test2"}, a)
	assert.Equal(t, []string{"mjwt:another"}, ps.Filter([]string{"mjwt:another"}).Dump())
}

func TestPermStorage_MarshalJSON(t *testing.T) {
	t.Parallel()
	ps := NewPermStorage()
	ps.Set("mjwt:test")
	ps.Set("mjwt:test2")
	b, err := ps.MarshalJSON()
	assert.NoError(t, err)
	assert.Equal(t, 0, bytes.Compare([]byte(`["mjwt:test","mjwt:test2"]`), b))
}

func TestPermStorage_MarshalYAML(t *testing.T) {
	t.Parallel()
	ps := NewPermStorage()
	ps.Set("mjwt:test")
	ps.Set("mjwt:test2")
	b, err := ps.MarshalYAML()
	assert.NoError(t, err)
	assert.Equal(t, 0, bytes.Compare([]byte("- mjwt:test\n- mjwt:test2\n"), b.([]byte)))
}
