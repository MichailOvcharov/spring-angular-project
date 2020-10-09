import {Component, Inject, OnInit, ViewChild} from '@angular/core';
import {MatTable} from "@angular/material/table";
import {SelectionModel} from "@angular/cdk/collections";
import {MAT_DIALOG_DATA, MatDialog, MatDialogRef} from "@angular/material/dialog";
import {CourseService} from "../../_service/course.service";
import {StudentService} from "../../_service/student.service";
import {Course} from "../../_model/course";
import {StudentList} from "../../_model/student-list";
import {AddInstrumentDialogComponent} from "../../room/room-edit-dialog/add-instrument-dialog/add-instrument-dialog.component";
import {AddStudentDialogComponent} from "./add-student-dialog/add-student-dialog.component";

@Component({
  selector: 'app-course-edit-dialog',
  templateUrl: './course-edit-dialog.component.html',
  styleUrls: ['./course-edit-dialog.component.scss']
})
export class CourseEditDialogComponent implements OnInit {
  @ViewChild(MatTable) studentTable: MatTable<StudentList>;

  data:Course = new Course();

  studentsDisplayedColumns: string [] = ['select', 'idd', 'firstName', 'middleName', 'lastName'];
  selection = new SelectionModel(false, []);
  showStudentTable:boolean = false;

  historyDisplayedColumns: string[] = ['id', 'name', 'startDate', 'endDate', 'deleteDate'];
  showHistoryTable:boolean = false;

  constructor(
    private _courseService:CourseService,
    private _studentService:StudentService,
    public dialogRef: MatDialogRef<CourseEditDialogComponent>,
    @Inject(MAT_DIALOG_DATA) public idd: number,
    public dialog: MatDialog) {}

  ngOnInit(): void {
    if (this.idd) {
      this._courseService.getCourseByIdd(this.idd)
        .pipe()
        .subscribe(course => {this.data = course});
    } else {
      this.data.students = [];
    }
  }

  setShowStudentTable() {
    this.showStudentTable = !this.showStudentTable;
  }

  setShowHistoryTable() {
    this.showHistoryTable = !this.showHistoryTable;
  }

  onCancelClick() {
    this.dialogRef.close();
  }

  onSaveClick() {
    if (this.idd){
      this._courseService.updateCourse(this.idd, this.data)
        .toPromise()
        .then(res => this.dialogRef.close())
        .catch(error => console.log(error));
    } else {
      this._courseService.createCourse(this.data)
        .toPromise()
        .then(res => this.dialogRef.close())
        .catch(error => console.log(error));
    }
  }

  onDeleteStudent() {
    this.data.students
      = this.data.students.filter(obj => obj.idd !== this.selection.selected[0].idd);
    this.selection.clear();
    this.studentTable.renderRows();
  }

  onAddStudent() {
    const dialogRef = this.dialog.open(AddStudentDialogComponent, {
      width: '750px'
    });

    dialogRef.afterClosed().subscribe(result => {
      this.data.students.push(result);
      this.studentTable.renderRows();
    });
  }
}
