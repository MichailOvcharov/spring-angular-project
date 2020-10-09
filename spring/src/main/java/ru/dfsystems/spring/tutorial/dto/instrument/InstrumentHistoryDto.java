package ru.dfsystems.spring.tutorial.dto.instrument;

import lombok.Getter;
import lombok.Setter;
import ru.dfsystems.spring.tutorial.dto.BaseHistoryDto;

@Getter
@Setter
public class InstrumentHistoryDto extends BaseHistoryDto {
    private String name;
    private String number;
}
