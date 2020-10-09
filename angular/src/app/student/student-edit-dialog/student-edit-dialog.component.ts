import {Component, Inject, OnInit, ViewChild} from '@angular/core';
import {MAT_DIALOG_DATA, MatDialog, MatDialogRef} from "@angular/material/dialog";
import {Room} from "../../_model/room";
import {RoomService} from "../../_service/room.service";
import {SelectionModel} from "@angular/cdk/collections";
//import {AddInstrumentDialogComponent} from "./add-instrument-dialog/add-instrument-dialog.component";
import {InstrumentService} from "../../_service/instrument.service";
import {MatTable} from "@angular/material/table";
import {Student} from "../../_model/student";
import {CourseList} from "../../_model/course-list";
import {StudentService} from "../../_service/student.service";
import {CourseService} from "../../_service/course.service";
import {AddInstrumentDialogComponent} from "../../room/room-edit-dialog/add-instrument-dialog/add-instrument-dialog.component";
import {AddCourseDialogComponent} from "./add-course-dialog/add-course-dialog.component";

@Component({
  selector: 'app-student-edit-dialog',
  templateUrl: './student-edit-dialog.component.html',
  styleUrls: ['./student-edit-dialog.component.scss']
})
export class StudentEditDialogComponent implements OnInit {
  @ViewChild(MatTable) courseTable: MatTable<CourseList>;

  data:Student = new Student();

  coursesDisplayedColumns: string [] = ['select', 'idd', 'name', 'startDate', 'endDate'];
  selection = new SelectionModel(false, []);
  showCourseTable:boolean = false;

  historyDisplayedColumns: string[] = ['id', 'lastName', 'firstName', 'passport', 'deleteDate'];
  showHistoryTable:boolean = false;

  constructor(
    private _studentService:StudentService,
    private _CourseService:CourseService,
    public dialogRef: MatDialogRef<StudentEditDialogComponent>,
    @Inject(MAT_DIALOG_DATA) public idd: number,
    public dialog: MatDialog) {}

  ngOnInit(): void {
    if (this.idd) {
      this._studentService.getStudentByIdd(this.idd)
        .pipe()
        .subscribe(student => {this.data = student});
    } else {
      this.data.courses = [];
    }
  }
  setShowCourseTable() {
    this.showCourseTable = !this.showCourseTable;
  }

  setShowHistoryTable() {
    this.showHistoryTable = !this.showHistoryTable;
  }

  onCancelClick() {
    this.dialogRef.close();
  }

  onSaveClick() {
    if (this.idd){
      this._studentService.updateStudent(this.idd, this.data)
        .toPromise()
        .then(res => this.dialogRef.close())
        .catch(error => console.log(error));
    } else {
      this._studentService.createStudent(this.data)
        .toPromise()
        .then(res => this.dialogRef.close())
        .catch(error => console.log(error));
    }
  }

  onDeleteCourse() {
    this.data.courses
      = this.data.courses.filter(obj => obj.idd !== this.selection.selected[0].idd);
    this.selection.clear();
    this.courseTable.renderRows();
  }

  onAddCourse() {
    const dialogRef = this.dialog.open(AddCourseDialogComponent, {
      width: '750px'
    });

    dialogRef.afterClosed().subscribe(result => {
      this.data.courses.push(result);
      this.courseTable.renderRows();
    });
  }
}
