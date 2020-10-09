import {Component, Inject, OnInit, ViewChild} from '@angular/core';
import {MatTable} from "@angular/material/table";
import {CourseList} from "../../_model/course-list";
import {SelectionModel} from "@angular/cdk/collections";
import {CourseService} from "../../_service/course.service";
import {MAT_DIALOG_DATA, MatDialog, MatDialogRef} from "@angular/material/dialog";
import {Teacher} from "../../_model/teacher";
import {TeacherService} from "../../_service/teacher.service";
import {AddCourseDialogComponent} from "../../student/student-edit-dialog/add-course-dialog/add-course-dialog.component";

@Component({
  selector: 'app-teacher-edit-dialog',
  templateUrl: './teacher-edit-dialog.component.html',
  styleUrls: ['./teacher-edit-dialog.component.scss']
})
export class TeacherEditDialogComponent implements OnInit {
  @ViewChild(MatTable) courseTable: MatTable<CourseList>;

  data:Teacher = new Teacher();

  coursesDisplayedColumns: string [] = ['select', 'idd', 'name', 'startDate', 'endDate'];
  selection = new SelectionModel(false, []);
  showCourseTable:boolean = false;

  historyDisplayedColumns: string[] = ['id', 'lastName', 'firstName', 'passport', 'deleteDate'];
  showHistoryTable:boolean = false;

  constructor(
    private _teacherService:TeacherService,
    private _CourseService:CourseService,
    public dialogRef: MatDialogRef<TeacherEditDialogComponent>,
    @Inject(MAT_DIALOG_DATA) public idd: number,
    public dialog: MatDialog) {}

  ngOnInit(): void {
    if (this.idd) {
      this._teacherService.getTeacherByIdd(this.idd)
        .pipe()
        .subscribe(teacher => {this.data = teacher});
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
      this._teacherService.updateTeacher(this.idd, this.data)
        .toPromise()
        .then(res => this.dialogRef.close())
        .catch(error => console.log(error));
    } else {
      this._teacherService.createTeacher(this.data)
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
