import {Component, Inject, OnInit, ViewChild} from '@angular/core';
import {MAT_DIALOG_DATA, MatDialog, MatDialogRef} from "@angular/material/dialog";
import {Room} from "../../_model/room";
import {RoomService} from "../../_service/room.service";
import {SelectionModel} from "@angular/cdk/collections";
import {AddInstrumentDialogComponent} from "./add-instrument-dialog/add-instrument-dialog.component";
import {InstrumentService} from "../../_service/instrument.service";
import {MatTable} from "@angular/material/table";
import {InstrumentList} from "../../_model/instrument-list";

@Component({
  selector: 'app-room-edit-dialog',
  templateUrl: './room-edit-dialog.component.html',
  styleUrls: ['./room-edit-dialog.component.scss']
})
export class RoomEditDialogComponent implements OnInit {
  @ViewChild(MatTable) instrumentTable: MatTable<InstrumentList>;

  data:Room = new Room();

  instrumentsDisplayedColumns: string [] = ['select', 'idd', 'name', 'number', 'createDate'];
  selection = new SelectionModel(false, []);
  showInstrumentTable:boolean = false;

  historyDisplayedColumns: string[] = ['id', 'number', 'block', 'deleteDate'];
  showHistoryTable:boolean = false;

  constructor(
    private _roomService:RoomService,
    private _instrumentService:InstrumentService,
    public dialogRef: MatDialogRef<RoomEditDialogComponent>,
    @Inject(MAT_DIALOG_DATA) public idd: number,
    public dialog: MatDialog) {}

  ngOnInit(): void {
    if (this.idd) {
      this._roomService.getRoomByIdd(this.idd)
        .pipe()
        .subscribe(room => {this.data = room});
    } else {
      this.data.instruments = [];
    }
  }

  setShowInstrumentTable() {
    this.showInstrumentTable = !this.showInstrumentTable;
  }

  setShowHistoryTable() {
    this.showHistoryTable = !this.showHistoryTable;
  }

  onCancelClick() {
    this.dialogRef.close();
  }

  onSaveClick() {
    if (this.idd){
      this._roomService.updateRoom(this.idd, this.data)
        .toPromise()
        .then(res => this.dialogRef.close())
        .catch(error => console.log(error));
    } else {
      this._roomService.createRoom(this.data)
        .toPromise()
        .then(res => this.dialogRef.close())
        .catch(error => console.log(error));
    }
  }

  onDeleteInstrument() {
    this.data.instruments
      = this.data.instruments.filter(obj => obj.idd !== this.selection.selected[0].idd);
    this.selection.clear();
    this.instrumentTable.renderRows();
  }

  onAddInstrument() {
    const dialogRef = this.dialog.open(AddInstrumentDialogComponent, {
      width: '750px'
    });

    dialogRef.afterClosed().subscribe(result => {
      this.data.instruments.push(result);
      this.instrumentTable.renderRows();
    });
  }
}
