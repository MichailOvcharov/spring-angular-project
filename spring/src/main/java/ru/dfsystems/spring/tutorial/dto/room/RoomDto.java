package ru.dfsystems.spring.tutorial.dto.room;

import lombok.Getter;
import lombok.Setter;
import ru.dfsystems.spring.tutorial.dto.BaseDto;
import ru.dfsystems.spring.tutorial.dto.instrument.InstrumentListDto;

import java.util.List;


@Getter
@Setter
public class RoomDto extends BaseDto<RoomHistoryDto> {
    private String number;
    private String block;

    private List<InstrumentListDto> instruments;
}
