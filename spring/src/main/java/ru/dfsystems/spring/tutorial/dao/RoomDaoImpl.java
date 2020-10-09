
package ru.dfsystems.spring.tutorial.dao;

import org.jooq.DSLContext;
import org.springframework.stereotype.Repository;
import ru.dfsystems.spring.tutorial.generated.Sequences;
import ru.dfsystems.spring.tutorial.generated.tables.daos.RoomDao;
import ru.dfsystems.spring.tutorial.generated.tables.pojos.Instrument;
import ru.dfsystems.spring.tutorial.generated.tables.pojos.Room;
import ru.dfsystems.spring.tutorial.security.UserContext;

import java.time.LocalDateTime;
import java.util.List;

import static ru.dfsystems.spring.tutorial.generated.tables.Instrument.INSTRUMENT;
import static ru.dfsystems.spring.tutorial.generated.tables.InstrumentToRoom.INSTRUMENT_TO_ROOM;
import static ru.dfsystems.spring.tutorial.generated.tables.Room.ROOM;

@Repository
public class RoomDaoImpl extends RoomDao implements BaseDao<Room> {
    private final DSLContext jooq;
    private UserContext userContext;

    public RoomDaoImpl(DSLContext jooq, UserContext userContext) {
        super(jooq.configuration());
        this.jooq = jooq;
        this.userContext = userContext;
    }

    public Room getActiveByIdd(Integer idd) {
        return jooq.select(ROOM.fields())
                .from(ROOM)
                .where(ROOM.IDD.eq(idd).and(ROOM.DELETE_DATE.isNull()))
                .fetchOneInto(Room.class);
    }

    public List<Room> getHistory(Integer idd) {
        return jooq.selectFrom(ROOM)
                .where(ROOM.IDD.eq(idd))
                .fetchInto(Room.class);
    }

    public Room create(Room room) {
        room.setId(jooq.nextval(Sequences.ROOM_ID_SEQ));
        if (room.getIdd() == null) {
            room.setIdd(room.getId());
        }
        room.setCreateDate(LocalDateTime.now());
        room.setUserId(userContext.getUser().getId());
        super.insert(room);
        return room;
    }

    public List<Room> getRoomsByInstrumentIdd(Integer idd) {
        return jooq.select(ROOM.fields())
                .from(ROOM)
                .join(INSTRUMENT_TO_ROOM)
                .on(ROOM.IDD.eq(INSTRUMENT_TO_ROOM.ROOM_IDD))
                .where(INSTRUMENT_TO_ROOM.INSTRUMENT_IDD.eq(idd))
                .fetchInto(Room.class);
    }
}
