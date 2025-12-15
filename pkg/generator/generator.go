package generator

import "idorplus/pkg/analyzer"

type PayloadGenerator struct {
	IDType    analyzer.IDType
	Numeric   *NumericGenerator
	UUID      *UUIDGenerator
	Encodings []string
	Encoder   *EncodingEngine
}

func NewPayloadGenerator(idType analyzer.IDType) *PayloadGenerator {
	return &PayloadGenerator{
		IDType:    idType,
		Numeric:   NewNumericGenerator(),
		UUID:      NewUUIDGenerator(),
		Encoder:   NewEncodingEngine(),
		Encodings: []string{}, // Add encodings here if needed
	}
}

func (pg *PayloadGenerator) Generate(count int) []string {
	var basePayloads []string

	switch pg.IDType {
	case analyzer.TypeNumeric:
		basePayloads = pg.Numeric.Generate(count)
	case analyzer.TypeUUID:
		basePayloads = pg.UUID.Generate(count)
	default:
		// Default to numeric if unknown
		basePayloads = pg.Numeric.Generate(count)
	}

	// Apply encodings if any
	if len(pg.Encodings) == 0 {
		return basePayloads
	}

	var encodedPayloads []string
	for _, p := range basePayloads {
		encodedPayloads = append(encodedPayloads, p) // Keep original
		for _, method := range pg.Encodings {
			encodedPayloads = append(encodedPayloads, pg.Encoder.Encode(p, method))
		}
	}

	return encodedPayloads
}
