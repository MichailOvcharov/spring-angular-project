import {HttpClient} from '@angular/common/http';
import {Component, ViewChild, AfterViewInit} from '@angular/core';
import {MatPaginator} from '@angular/material/paginator';
import {MatSort} from '@angular/material/sort';
import {merge, Observable, of as observableOf} from 'rxjs';
import {catchError, map, startWith, switchMap} from 'rxjs/operators';
import {StudentList} from "../_model/student-list";
import {StudentService} from "../_service/student.service";
import {RoomEditDialogComponent} from "../room/room-edit-dialog/room-edit-dialog.component";
import {SelectionModel} from "@angular/cdk/collections";
import {RoomService} from "../_service/room.service";
import {MatDialog} from "@angular/material/dialog";
import {StudentEditDialogComponent} from "./student-edit-dialog/student-edit-dialog.component";
import {Student} from "../_model/student";
import {MatTable} from "@angular/material/table";
import {CourseList} from "../_model/course-list";


@Component({
  selector: 'app-student',
  templateUrl: './student.component.html',
  styleUrls: ['./student.component.scss']
})
export class StudentComponent implements AfterViewInit {
  sizeOption: number[] = [2, 5, 10];
  displayedColumns: string[] = ['select', 'idd', 'lastName', 'firstName', 'middleName', 'passport', 'birthDate', /*'status',*/  'createDate'];
  data: Student[];
  selection = new SelectionModel<Student>(false, []);
  constructor(private _studentService: StudentService, public dialog: MatDialog) {}

  resultsLength = 0;
  isLoadingResults = true;
  isRateLimitReached = false;

  @ViewChild(MatTable) studentTable: MatTable<StudentList>;
  @ViewChild(MatPaginator) paginator: MatPaginator;
  @ViewChild(MatSort) sort: MatSort;

  ngAfterViewInit(): void {
    this.sort.sortChange.subscribe(() => this.paginator.pageIndex = 0);

    this.refresh();
  }

  openEditDialog() {
    const dialogRef = this.dialog.open(StudentEditDialogComponent, {
      width: '750px',
      data: this.selection.selected[0]?.idd
    });

    dialogRef.afterClosed().subscribe(result => {
      this.refresh();
    });
  }

  onDeleteStudent() {
    if (this.selection.selected[0] == null) {
      return;
    }
    this._studentService.deleteStudent(this.selection.selected[0].idd);
    this.selection.clear();
    this.refresh();
  }
  // this.studentTable.renderRows();
  // this.data
  //   = this.data.filter(obj => obj.idd !== this.selection.selected[0].idd);
  // this.data.instruments
  //   = this.data.instruments.filter(obj => obj.idd !== this.selection.selected[0].idd);
  // this.selection.clear();
  // this.instrumentTable.renderRows();

  refresh() {
    merge(this.sort.sortChange, this.paginator.page)
      .pipe(
        startWith({}),
        switchMap(() => {
          this.isLoadingResults = true;
          return this._studentService.getStudentList(
            this.sort.active, this.sort.direction, this.paginator.pageIndex, this.paginator.pageSize);
        }),
        map(data => {
          // Flip flag to show that loading has finished.
          this.isLoadingResults = false;
          this.isRateLimitReached = false;
          this.resultsLength = data.totalCount;

          return data.list;
        }),
        catchError(() => {
          this.isLoadingResults = false;
          // Catch if the GitHub API has reached its rate limit. Return empty data.
          this.isRateLimitReached = true;
          return observableOf([]);
        })
      ).subscribe(data => this.data = data);
  }
}
