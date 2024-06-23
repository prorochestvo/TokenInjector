package shifting

func Marshal(dataset []byte, bitrate int) ([]byte, error) {
	return shiftingToLeft(dataset, bitrate), nil
}

func Unmarshal(dataset []byte, bitrate int) ([]byte, error) {
	return shiftingToRight(dataset, bitrate), nil
}

// shifting to left
func shiftingToLeft(dataset []byte, bits int) []byte {
	l := len(dataset)
	if l == 0 {
		return dataset
	}

	index := (bits / 8) % l
	if index != 0 && l > 1 {
		dataset = append(dataset[index:], dataset[:index]...)
	}

	bits = bits % 8
	if bits != 0 {
		var tmp byte = 0
		var v byte = 0

		for i, d := range dataset {
			dataset[i] = d << bits
			v = (d & ((0xFF >> bits) ^ 0xFF)) >> (8 - bits)
			if i == 0 {
				tmp = v
			} else {
				dataset[i-1] = dataset[i-1] | v
			}
		}

		if tmp != 0 {
			dataset[l-1] = dataset[l-1] | tmp
		}
	}

	return dataset
}

// shifting within ony byte
func shiftingToRight(dataset []byte, bits int) []byte {
	l := len(dataset)
	if l == 0 {
		return dataset
	}

	index := (bits / 8) % l
	if index != 0 && l > 1 {
		index = l - index
		dataset = append(dataset[index:], dataset[:index]...)
	}

	bits = bits % 8
	if bits != 0 {
		var tmp byte = 0

		for i, d := range dataset {
			dataset[i] = tmp | (d >> bits)
			tmp = (d & ((0xFF << bits) ^ 0xFF)) << (8 - bits)
		}

		if tmp != 0 {
			dataset[0] = dataset[0] | tmp
		}
	}

	return dataset
}
