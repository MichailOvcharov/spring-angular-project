import { Injectable } from '@angular/core';
import {HttpClient} from "@angular/common/http";
import {Observable} from "rxjs";
import {Page} from "../_model/page";
import {PageParams} from "../_model/page-params";
import {Student} from "../_model/student";

@Injectable({
  providedIn: 'root'
})
export class StudentService {
  constructor(private _httpClient: HttpClient) {}

  getStudentList(sort: string, order: string, page: number, pageSize: number): Observable<Page> {
    const href = '/api/student/list';

    return this._httpClient.post<Page>(href, new PageParams(page*pageSize, pageSize, {
      orderBy:sort,
      orderDir:order
    }));
  }
  getStudentByIdd(idd: number): Observable<Student> {
    const href = '/api/student/' + idd;

    return this._httpClient.get<Student>(href);
  }

  updateStudent(idd: number, data: Student):Observable<Object> {
    const href = '/api/student/' + idd;
    return this._httpClient.patch(href, data);
  }

  createStudent(data: Student):Observable<Object> {
    const href = '/api/student';
    return this._httpClient.post(href, data);
  }

  deleteStudent(idd: number) {
    const href = '/api/student/' + idd;
    return this._httpClient.delete(href).subscribe(data => {
      console.log(data);
    });
  }
}
