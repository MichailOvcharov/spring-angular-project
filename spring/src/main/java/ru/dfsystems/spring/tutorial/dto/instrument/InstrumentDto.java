package ru.dfsystems.spring.tutorial.dto.instrument;

import lombok.Getter;
import lombok.Setter;
import ru.dfsystems.spring.tutorial.dto.BaseDto;
import ru.dfsystems.spring.tutorial.dto.room.RoomListDto;

import java.util.List;

@Getter
@Setter
public class InstrumentDto extends BaseDto<InstrumentHistoryDto> {
    private String name;
    private String number;
    private List<RoomListDto> rooms;
}
