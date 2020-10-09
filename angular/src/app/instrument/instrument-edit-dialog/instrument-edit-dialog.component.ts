import {Component, Inject, OnInit, ViewChild} from '@angular/core';
import {MatTable} from "@angular/material/table";
import {InstrumentList} from "../../_model/instrument-list";
import {Room} from "../../_model/room";
import {SelectionModel} from "@angular/cdk/collections";
import {Instrument} from "../../_model/instrument";
import {RoomService} from "../../_service/room.service";
import {InstrumentService} from "../../_service/instrument.service";
import {MAT_DIALOG_DATA, MatDialog, MatDialogRef} from "@angular/material/dialog";
import {AddInstrumentDialogComponent} from "../../room/room-edit-dialog/add-instrument-dialog/add-instrument-dialog.component";
import {RoomList} from "../../_model/room-list";
import {AddRoomDialogComponent} from "./add-room-dialog/add-room-dialog.component";

@Component({
  selector: 'app-instrument-edit-dialog',
  templateUrl: './instrument-edit-dialog.component.html',
  styleUrls: ['./instrument-edit-dialog.component.scss']
})
export class InstrumentEditDialogComponent implements OnInit {
  @ViewChild(MatTable) roomTable: MatTable<RoomList>;

  data:Instrument = new Instrument();

  roomsDisplayedColumns: string [] = ['select', 'idd', 'number', 'block', 'createDate'];
  selection = new SelectionModel(false, []);
  showRoomTable:boolean = false;

  historyDisplayedColumns: string[] = ['id', 'name', 'number', 'deleteDate'];
  showHistoryTable:boolean = false;

  constructor(
    private _roomService:RoomService,
    private _instrumentService:InstrumentService,
    public dialogRef: MatDialogRef<InstrumentEditDialogComponent>,
    @Inject(MAT_DIALOG_DATA) public idd: number,
    public dialog: MatDialog) { }

  ngOnInit(): void {
    if (this.idd) {
      this._instrumentService.getInstrumentByIdd(this.idd)
        .pipe()
        .subscribe(instrument => {this.data = instrument});
    } else {
      this.data.rooms = [];
    }
  }

  setShowInstrumentTable() {
    this.showRoomTable = !this.showRoomTable;
  }

  setShowHistoryTable() {
    this.showHistoryTable = !this.showHistoryTable;
  }

  onCancelClick() {
    this.dialogRef.close();
  }

  onSaveClick() {
    if (this.idd){
      this._instrumentService.updateInstrument(this.idd, this.data)
        .toPromise()
        .then(res => this.dialogRef.close())
        .catch(error => console.log(error));
    } else {
      this._instrumentService.createInstrument(this.data)
        .toPromise()
        .then(res => this.dialogRef.close())
        .catch(error => console.log(error));
    }
  }

  onDeleteRoom() {
    this.data.rooms
      = this.data.rooms.filter(obj => obj.idd !== this.selection.selected[0].idd);
    this.selection.clear();
    this.roomTable.renderRows();
  }

  onAddRoom() {
    const dialogRef = this.dialog.open(AddRoomDialogComponent, {
      width: '750px'
    });

    dialogRef.afterClosed().subscribe(result => {
      this.data.rooms.push(result);
      this.roomTable.renderRows();
    });
  }

}
