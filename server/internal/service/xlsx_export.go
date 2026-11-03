package service

import (
	"fmt"
	"io"
	"unicode/utf8"

	"github.com/xuri/excelize/v2"
)

const (
	exportCellRunes = 16000 // Stays below Excel's 32767 UTF-16 code unit limit.
	exportMaxRow    = 1048576
)

func writeExportWorkbook(output io.Writer, sheetName string, headers []interface{}, widths []float64, each func(func([]interface{}) error) error) (err error) {
	if len(headers) != len(widths) {
		return fmt.Errorf("XLSX export column count mismatch")
	}
	book := excelize.NewFile()
	defer func() {
		if closeErr := book.Close(); err == nil {
			err = closeErr
		}
	}()
	if err := book.SetSheetName("Sheet1", sheetName); err != nil {
		return err
	}
	if _, err := book.NewSheet("large_fields"); err != nil {
		return err
	}
	main, err := book.NewStreamWriter(sheetName)
	if err != nil {
		return err
	}
	large, err := book.NewStreamWriter("large_fields")
	if err != nil {
		return err
	}
	headerStyle, bodyStyles, nameStyles, err := prepareExportStyles(book)
	if err != nil {
		return err
	}
	for index, width := range widths {
		if err := main.SetColWidth(index+1, index+1, width); err != nil {
			return err
		}
	}
	for index, width := range []float64{12, 26, 10, 100} {
		if err := large.SetColWidth(index+1, index+1, width); err != nil {
			return err
		}
	}
	if err := main.SetPanes(&excelize.Panes{Freeze: true, XSplit: 1, YSplit: 1, TopLeftCell: "B2", ActivePane: "bottomRight"}); err != nil {
		return err
	}
	if err := large.SetPanes(&excelize.Panes{Freeze: true, XSplit: 3, YSplit: 1, TopLeftCell: "D2", ActivePane: "bottomRight"}); err != nil {
		return err
	}
	if err := main.SetRow("A1", headers, excelize.RowOpts{Height: 34, StyleID: headerStyle}); err != nil {
		return err
	}
	if err := large.SetRow("A1", []interface{}{"row", "field", "part", "content"}, excelize.RowOpts{Height: 34, StyleID: headerStyle}); err != nil {
		return err
	}
	row, largeRow := 1, 1
	err = each(func(values []interface{}) error {
		if len(values) != len(headers) {
			return fmt.Errorf("XLSX export row column count mismatch")
		}
		if row == exportMaxRow {
			return fmt.Errorf("XLSX data row limit exceeded")
		}
		row++
		for column, value := range values {
			content, ok := value.(string)
			if !ok || utf8.RuneCountInString(content) <= exportCellRunes {
				continue
			}
			part := 0
			for len(content) > 0 {
				if largeRow == exportMaxRow {
					return fmt.Errorf("XLSX large field row limit exceeded")
				}
				chunk, remaining := splitExportCell(content)
				part++
				largeRow++
				if err := large.SetRow(fmt.Sprintf("A%d", largeRow), []interface{}{row, headers[column], part, chunk}, excelize.RowOpts{Height: 84, StyleID: bodyStyles[largeRow%2]}); err != nil {
					return err
				}
				content = remaining
			}
			values[column] = "[see large_fields]"
		}
		values[0] = excelize.Cell{StyleID: nameStyles[row%2], Value: values[0]}
		return main.SetRow(fmt.Sprintf("A%d", row), values, excelize.RowOpts{Height: 48, StyleID: bodyStyles[row%2]})
	})
	if err != nil {
		return err
	}
	if err := main.Flush(); err != nil {
		return err
	}
	if err := large.Flush(); err != nil {
		return err
	}
	return book.Write(output)
}

func prepareExportStyles(book *excelize.File) (int, [2]int, [2]int, error) {
	header, err := book.NewStyle(&excelize.Style{
		Font:      &excelize.Font{Family: "Arial", Size: 11, Bold: true, Color: "FFFFFF"},
		Fill:      excelize.Fill{Type: "pattern", Color: []string{"165A66"}, Pattern: 1},
		Alignment: &excelize.Alignment{Horizontal: "left", Vertical: "center", WrapText: true, Indent: 1},
	})
	if err != nil {
		return 0, [2]int{}, [2]int{}, err
	}
	var bodies, names [2]int
	for index, background := range []string{"FFFFFF", "F2F7F8"} {
		base := excelize.Style{
			Font:      &excelize.Font{Family: "Arial", Size: 10, Color: "24323D"},
			Fill:      excelize.Fill{Type: "pattern", Color: []string{background}, Pattern: 1},
			Border:    []excelize.Border{{Type: "bottom", Color: "DDE6E9", Style: 1}},
			Alignment: &excelize.Alignment{Vertical: "center", WrapText: true},
		}
		bodies[index], err = book.NewStyle(&base)
		if err != nil {
			return 0, [2]int{}, [2]int{}, err
		}
		base.Font = &excelize.Font{Family: "Arial", Size: 10, Bold: true, Color: "165A66"}
		names[index], err = book.NewStyle(&base)
		if err != nil {
			return 0, [2]int{}, [2]int{}, err
		}
	}
	return header, bodies, names, nil
}

func splitExportCell(value string) (string, string) {
	count := 0
	for index := range value {
		if count == exportCellRunes {
			return value[:index], value[index:]
		}
		count++
	}
	return value, ""
}
