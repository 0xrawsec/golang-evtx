package evtx

import (
	"fmt"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type GoEvtxElement interface{}

type GoEvtxMap map[string]interface{}

type GoEvtxPath []string

func (p GoEvtxPath) String() string {
	return strings.Join(p, "/")
}

type ErrEvtxEltNotFound struct {
	path GoEvtxPath
}

func (e *ErrEvtxEltNotFound) Error() string {
	return fmt.Sprintf("Element at path %v not found", e.path)
}

// Path : helper function that converts a path string to a table of strings
// @s : path string, has to be in form of /correct/path/string with (correct,
// path, string) being keys to look for recursively
func Path(s string) GoEvtxPath {
	return strings.Split(strings.Trim(s, PathSeparator), PathSeparator)
}

// HasKeys : determines whether this map is in a key value form
// return bool
func (pg *GoEvtxMap) HasKeys(keys ...string) bool {
	for _, k := range keys {
		if _, ok := (*pg)[k]; !ok {
			return false
		}
	}
	return true
}

// Add : concatenate two GoEvtxMap together
// @other: other map to concatenate with
func (pg *GoEvtxMap) Add(other GoEvtxMap) {
	for k, v := range other {
		if _, ok := (*pg)[k]; ok {
			panic("Duplicated key")
		}
		(*pg)[k] = v
	}
}

// GetMap : Get the full map containing the path
// @path : path to search for
func (pg *GoEvtxMap) GetMap(path *GoEvtxPath) (*GoEvtxMap, error) {
	if len(*path) > 0 {
		if ge, ok := (*pg)[(*path)[0]]; ok {
			if len(*path) == 1 {
				return pg, nil
			}
			switch ge.(type) {
			case GoEvtxMap:
				p := ge.(GoEvtxMap)
				np := (*path)[1:]
				return p.GetMap(&np)
			}
		}
	}
	return nil, &ErrEvtxEltNotFound{*path}
}

func (pg *GoEvtxMap) GetMapStrict(path *GoEvtxPath) *GoEvtxMap {
	pg, err := pg.GetMap(path)
	if err != nil {
		panic(err)
	}
	return pg
}

func (pg *GoEvtxMap) GetMapWhere(path *GoEvtxPath, value interface{}) (*GoEvtxMap, error) {
	m, err := pg.GetMap(path)
	if err != nil {
		return nil, err
	}
	if m != nil && len(*path) > 0 {
		np := (*path)[len(*path)-1:]
		if m.Equal(&np, value) {
			return m, nil
		}
	}
	return nil, &ErrEvtxEltNotFound{*path}
}

func (pg *GoEvtxMap) GetMapWhereStrict(path *GoEvtxPath, value interface{}) *GoEvtxMap {
	pg, err := pg.GetMapWhere(path, value)
	if err != nil {
		panic(err)
	}
	return pg
}

// Recursive search in a GoEvtxMap according to a given path
// @path : path to search for
// return *GoEvtxElement, error : pointer to the element found at path
func (pg *GoEvtxMap) Get(path *GoEvtxPath) (*GoEvtxElement, error) {
	if len(*path) > 0 {
		if i, ok := (*pg)[(*path)[0]]; ok {
			if len(*path) == 1 {
				cge := GoEvtxElement(i)
				return &cge, nil
			}
			switch i.(type) {
			case GoEvtxMap:
				p := i.(GoEvtxMap)
				np := (*path)[1:]
				return p.Get(&np)
			case map[string]interface{}:
				p := GoEvtxMap(i.(map[string]interface{}))
				np := (*path)[1:]
				return p.Get(&np)
			}
		}
	}
	return nil, &ErrEvtxEltNotFound{*path}
}

func (pg *GoEvtxMap) GetStrict(path *GoEvtxPath) *GoEvtxElement {
	gee, err := pg.Get(path)
	if err != nil {
		panic(err)
	}
	return gee
}

// GetUint returns the GoEvtxElement at path as a string
// @path : path to search for
// return string, error
func (pg *GoEvtxMap) GetString(path *GoEvtxPath) (string, error) {
	pE, err := pg.Get(path)
	if err != nil {
		return "", err
	}
	if s, ok := (*pE).(string); ok {
		return s, nil
	}
	return "", fmt.Errorf("Bad type expect string got %T", (*pE))
}

func (pg *GoEvtxMap) GetStringStrict(path *GoEvtxPath) string {
	s, err := pg.GetString(path)
	if err != nil {
		panic(err)
	}
	return s
}

// GetBool returns the GoEvtxElement at path as a bool
// @path : path to search for
// return (bool, error)
func (pg *GoEvtxMap) GetBool(path *GoEvtxPath) (bool, error) {
	s, err := pg.GetString(path)
	if err != nil {
		return false, &ErrEvtxEltNotFound{*path}
	}
	b, err := strconv.ParseBool(s)
	if err != nil {
		return false, err
	}
	return b, err
}

func (pg *GoEvtxMap) GetBoolStrict(path *GoEvtxPath) bool {
	b, err := pg.GetBool(path)
	if err != nil {
		panic(err)
	}
	return b
}

// GetInt returns the GoEvtxElement at path as a int64
// @path : path to search for
// return int64, error
func (pg *GoEvtxMap) GetInt(path *GoEvtxPath) (int64, error) {
	s, err := pg.GetString(path)
	if err != nil {
		return 0, &ErrEvtxEltNotFound{*path}
	}
	i, err := strconv.ParseInt(s, 0, 64)
	if err != nil {
		return 0, err
	}
	return i, nil
}

func (pg *GoEvtxMap) GetIntStrict(path *GoEvtxPath) int64 {
	i, err := pg.GetInt(path)
	if err != nil {
		panic(err)
	}
	return i
}

// GetUint returns the GoEvtxElement at path as a uint64
// @path : path to search for
// return uint64
func (pg *GoEvtxMap) GetUint(path *GoEvtxPath) (uint64, error) {
	s, err := pg.GetString(path)
	if err != nil {
		return 0, &ErrEvtxEltNotFound{*path}
	}
	u, err := strconv.ParseUint(s, 0, 64)
	if err != nil {
		return 0, err
	}
	return u, nil
}

func (pg *GoEvtxMap) GetUintStrict(path *GoEvtxPath) uint64 {
	u, err := pg.GetUint(path)
	if err != nil {
		panic(err)
	}
	return u
}

// GetUint returns the GoEvtxElement at path as a Time struct
// @path : path to search for
// return Time
func (pg *GoEvtxMap) GetTime(path *GoEvtxPath) (time.Time, error) {
	t, err := pg.Get(path)
	if err != nil {
		return time.Time{}, &ErrEvtxEltNotFound{*path}
	}
	// If the value was extracted from raw BinXML (not a template) it may happen
	// that the value stored at path is a string since in raw BinXML everything
	// seems to be ValueText
	switch (*t).(type) {
	case time.Time:
		return (*t).(time.Time), nil
	case UTCTime:
		return time.Time((*t).(UTCTime)), nil
	case string:
		return time.Parse(time.RFC3339Nano, (*t).(string))
	default:
		return time.Time{}, fmt.Errorf("Cannot convert %T to time.Time", *t)
	}
}

func (pg *GoEvtxMap) GetTimeStrict(path *GoEvtxPath) time.Time {
	t, err := pg.GetTime(path)
	if err != nil {
		panic(err)
	}
	return t
}

// EventID returns the EventID of the Event as a int64
// return int64 : EventID
func (pg *GoEvtxMap) EventID() int64 {
	eid, err := pg.GetInt(&EventIDPath)
	if err != nil {
		eid, err = pg.GetInt(&EventIDPath2)
		if err != nil {
			panic(err)
		}
		return eid
	}
	return eid
}

// Channel returns the Channel attribute of the event
// return string : Channel attribute
func (pg *GoEvtxMap) Channel() string {
	return pg.GetStringStrict(&ChannelPath)
}

// EventRecordID returns the EventRecordID of the the event. It panics if the
// attribute is not found in the event.
func (pg *GoEvtxMap) EventRecordID() int64 {
	return pg.GetIntStrict(&EventRecordIDPath)
}

// TimeCreated returns the creation time of the event. It panics if the attribute
// is not in the event
func (pg *GoEvtxMap) TimeCreated() time.Time {
	return pg.GetTimeStrict(&SystemTimePath)
}

// UserID retrieves the UserID attribute located at /Event/System/Security/UserID
// if present. If not present the ok flag will be false
func (pg *GoEvtxMap) UserID() (userID string, ok bool) {
	userID, err := pg.GetString(&UserIDPath)
	if err == nil {
		ok = true
	}
	return
}

func (pg *GoEvtxMap) Before(t time.Time) bool {
	return pg.GetTimeStrict(&SystemTimePath).Before(t)
}

func (pg *GoEvtxMap) After(t time.Time) bool {
	return pg.GetTimeStrict(&SystemTimePath).After(t)
}

func (pg *GoEvtxMap) At(t time.Time) bool {
	return pg.GetTimeStrict(&SystemTimePath).Equal(t)
}

func (pg *GoEvtxMap) Between(t1, t2 time.Time) bool {
	return (pg.After(t1) || pg.At(t1)) && (pg.Before(t2) || pg.At(t2))
}

// Equal returns true if element at path is equal to i
// @path : path at witch GoEvtxElement is located
// @i : interface to test equality with
// return bool : true if equality is verified
func (pg *GoEvtxMap) Equal(path *GoEvtxPath, i interface{}) bool {
	t, err := pg.Get(path)
	if err != nil {
		return false
	}
	return reflect.DeepEqual(*t, i)
}

// Equal returns true if element at path is equal to any object
// @path : path at witch GoEvtxElement is located
// @is : slice of interface to test equality with
// return bool : true if equality is verified
func (pg *GoEvtxMap) AnyEqual(path *GoEvtxPath, is []interface{}) bool {
	t, err := pg.Get(path)
	if err != nil {
		return false
	}
	for _, i := range is {
		if reflect.DeepEqual(i, *t) {
			return true
		}
	}
	return false
}

// RegexMatch returns true if GoEvtxElement located at path matches a regexp
// @path : path at witch GoEvtxElement is located
// @pattern : regexp to test
// return bool
func (pg *GoEvtxMap) RegexMatch(path *GoEvtxPath, pattern *regexp.Regexp) bool {
	s, err := pg.GetString(path)
	if err != nil {
		return false
	}
	return pattern.MatchString(s)
}

// IsEventID returns true if pg is one of the EventID number specified in parameter
// @eids : EventID numbers to test against
// return bool
func (pg *GoEvtxMap) IsEventID(eids ...interface{}) bool {
	return pg.AnyEqual(&EventIDPath, eids)
}

// Set sets a new GoEvtxElement at path
// @path... : path to look for
// @new : new value
// return error if any
func (pg *GoEvtxMap) Set(path *GoEvtxPath, new GoEvtxElement) error {
	if len(*path) > 0 {
		i := (*pg)[(*path)[0]]
		if len(*path) == 1 {
			(*pg)[(*path)[0]] = new
			return nil
		}
		switch i.(type) {
		case GoEvtxMap:
			p := i.(GoEvtxMap)
			np := (*path)[1:]
			return p.Set(&np, new)
		case map[string]interface{}:
			p := GoEvtxMap(i.(map[string]interface{}))
			np := (*path)[1:]
			return p.Set(&np, new)
		}

	}
	return &ErrEvtxEltNotFound{*path}
}

// Del deletes the object referenced by path
func (pg *GoEvtxMap) Del(path ...string) {
	if len(path) > 0 {
		if ge, ok := (*pg)[path[0]]; ok {
			if len(path) == 1 {
				delete((*pg), path[0])
			}
			switch ge.(type) {
			case GoEvtxMap:
				p := ge.(GoEvtxMap)
				p.Del(path[1:]...)
			}
		}
	}
}

// DelXmlns : utility function to delete useless xlmns entry found in every
// GoEvtxMap
func (pg *GoEvtxMap) DelXmlns() {
	pg.Del(XmlnsPath...)
}
