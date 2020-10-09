import {HttpClient} from "@angular/common/http";
import {Observable} from "rxjs";
import {Page} from "../_model/page";
import {PageParams} from "../_model/page-params";
import { Injectable } from '@angular/core';
import {Room} from "../_model/room";
import {Lesson} from "../_model/lesson";

@Injectable({
  providedIn: 'root'
})

export class LessonService {
  constructor(private _httpClient: HttpClient) {}

  getLessonList(sort: string, order: string, page: number, pageSize: number): Observable<Page> {
    const href = '/api/lesson/list';

    return this._httpClient.post<Page>(href, new PageParams(page*pageSize, pageSize, {
      orderBy:sort,
      orderDir:order
    }));
  }

  getLessonByIdd(idd: number): Observable<Lesson> {
    const href = '/api/lesson/' + idd;

    return this._httpClient.get<Lesson>(href);
  }

  updateLesson(idd: number, data: Lesson):Observable<Object> {
    const href = '/api/lesson/' + idd;
    return this._httpClient.patch(href, data);
  }

  createLesson(data: Lesson):Observable<Object> {
    const href = '/api/lesson';
    return this._httpClient.post(href, data);
  }

  deleteLesson(idd: number) {
    const href = '/api/lesson/' + idd;
    return this._httpClient.delete(href).subscribe(data => {
      console.log(data);
    });
  }
}
