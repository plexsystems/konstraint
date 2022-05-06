package commands

import (
	"reflect"
	"testing"
)

func TestToInterfaceSlice(t *testing.T) {
	type args struct {
		input []string
	}
	tests := []struct {
		name string
		args args
		want []interface{}
	}{
		{
			"empty",
			args{[]string{}},
			[]interface{}{},
		},
		{
			"valid",
			args{[]string{"a", "b"}},
			[]interface{}{"a", "b"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := toInterfaceSlice(tt.args.input); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("toInterfaceSlice() = %v, want %v", got, tt.want)
			}
		})
	}
}
