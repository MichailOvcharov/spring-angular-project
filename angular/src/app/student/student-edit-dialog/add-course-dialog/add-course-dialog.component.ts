import { Component, OnInit } from '@angular/core';
import {MatDialogRef} from "@angular/material/dialog";
import {CourseService} from "../../../_service/course.service";
import {CourseList} from "../../../_model/course-list";

@Component({
  selector: 'app-add-course-dialog',
  templateUrl: './add-course-dialog.component.html',
  styleUrls: ['./add-course-dialog.component.scss']
})
export class AddCourseDialogComponent implements OnInit {
  courses: CourseList[] = [];
  selected:number;

  constructor(public dialogRef: MatDialogRef<AddCourseDialogComponent>, private _courseService: CourseService) { }

  ngOnInit(): void {
    this._courseService.getCourseList(null, null, 0, 1000)
      .pipe()
      .subscribe(res => this.courses = res.list)
  }

  onCancelClick() {
    this.dialogRef.close();
  }

  onSaveClick() {
    this.dialogRef.close(this.selected);
  }
}
