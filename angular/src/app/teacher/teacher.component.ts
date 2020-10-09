import {AfterViewInit, Component, OnInit, ViewChild} from '@angular/core';
import {MatPaginator} from '@angular/material/paginator';
import {MatSort} from '@angular/material/sort';
import {merge, Observable, of as observableOf} from 'rxjs';
import {catchError, map, startWith, switchMap} from 'rxjs/operators';
import {Teacher} from "../_model/teacher";
import {TeacherService} from "../_service/teacher.service";
// import {StudentList} from "../_model/student";
import {StudentService} from "../_service/student.service";
import {TeacherList} from "../_model/teacher-list";
import {SelectionModel} from "@angular/cdk/collections";
import {MatDialog} from "@angular/material/dialog";
import {StudentEditDialogComponent} from "../student/student-edit-dialog/student-edit-dialog.component";
import {TeacherEditDialogComponent} from "./teacher-edit-dialog/teacher-edit-dialog.component";

@Component({
  selector: 'app-teacher',
  templateUrl: './teacher.component.html',
  styleUrls: ['./teacher.component.scss']
})
export class TeacherComponent implements AfterViewInit {
  sizeOption:number[] = [2, 5, 10];
  displayedColumns: string[] = ['select', 'idd', 'lastName', 'firstName', 'middleName', 'passport', 'birthDate', 'createDate'];
  data: TeacherList[];
  selection = new SelectionModel<TeacherList>(false, []);
  constructor(private _teacherService: TeacherService, public dialog: MatDialog) {}

  resultsLength = 0;
  isLoadingResults = true;
  isRateLimitReached = false;

  @ViewChild(MatPaginator) paginator: MatPaginator;
  @ViewChild(MatSort) sort: MatSort;

  ngAfterViewInit(): void {
    this.sort.sortChange.subscribe(() => this.paginator.pageIndex = 0);
    this.refresh();
  }

  openEditDialog() {
    const dialogRef = this.dialog.open(TeacherEditDialogComponent, {
      width: '750px',
      data: this.selection.selected[0]?.idd
    });

    dialogRef.afterClosed().subscribe(result => {
      this.refresh();
    });
  }

  refresh() {
    merge(this.sort.sortChange, this.paginator.page)
      .pipe(
        startWith({}),
        switchMap(() => {
          this.isLoadingResults = true;
          return this._teacherService.getTeacherList(
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
  onDeleteTeacher() {
    if (this.selection.selected[0] == null) {
      return;
    }
    this._teacherService.deleteTeacher(this.selection.selected[0].idd);
    this.selection.clear();
    this.refresh();
  }
}
