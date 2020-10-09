import {Component, Inject, OnInit, ViewChild} from '@angular/core';
import {MatTable} from "@angular/material/table";
import {InstrumentList} from "../../_model/instrument-list";
import {Room} from "../../_model/room";
import {SelectionModel} from "@angular/cdk/collections";
import {InstrumentService} from "../../_service/instrument.service";
import {MAT_DIALOG_DATA, MatDialog, MatDialogRef} from "@angular/material/dialog";
import {Lesson} from "../../_model/lesson";
import {LessonService} from "../../_service/lesson.service";
import {AddInstrumentDialogComponent} from "../../room/room-edit-dialog/add-instrument-dialog/add-instrument-dialog.component";

@Component({
  selector: 'app-lesson-edit-dialog',
  templateUrl: './lesson-edit-dialog.component.html',
  styleUrls: ['./lesson-edit-dialog.component.scss']
})
export class LessonEditDialogComponent implements OnInit {
  @ViewChild(MatTable) instrumentTable: MatTable<InstrumentList>;

  data:Lesson = new Lesson();

  instrumentsDisplayedColumns: string [] = ['select', 'idd', 'name', 'number', 'createDate'];
  selection = new SelectionModel(false, []);
  showInstrumentTable:boolean = false;

  historyDisplayedColumns: string[] = ['id', 'name', 'description', 'deleteDate'];
  showHistoryTable:boolean = false;

  constructor(
    private _lessonService: LessonService,
    private _instrumentService:InstrumentService,
    public dialogRef: MatDialogRef<LessonEditDialogComponent>,
    @Inject(MAT_DIALOG_DATA) public idd: number,
    public dialog: MatDialog) {}

  ngOnInit(): void {
    if (this.idd) {
      this._lessonService.getLessonByIdd(this.idd)
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
    if (this.idd) {
      this._lessonService.updateLesson(this.idd, this.data)
        .toPromise()
        .then(res => this.dialogRef.close())
        .catch(error => console.log(error));
    } else {
      this._lessonService.createLesson(this.data)
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
