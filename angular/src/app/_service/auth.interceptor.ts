import {HttpErrorResponse, HttpEvent, HttpHandler, HttpInterceptor, HttpRequest} from "@angular/common/http";
import {Injectable} from "@angular/core";
import {Observable, of, throwError} from "rxjs";
import {Router} from "@angular/router";
import {catchError} from "rxjs/operators";
import {MatDialog} from "@angular/material/dialog";
import {ErrorDialogComponent} from "../error-dialog/error-dialog.component";

@Injectable()
export class AuthInterceptor implements HttpInterceptor{

  constructor(private router: Router, private dialog:MatDialog){}

  intercept(req: HttpRequest<any>, next: HttpHandler): Observable<HttpEvent<any>> {
    return next.handle(req).pipe(catchError(x => this.handleAuthError(x)));
  }

  private handleAuthError(err: HttpErrorResponse): Observable<any>{
    if (err.status === 401 || err.status === 403) {
      this.router.navigateByUrl('/login');
      return of(err.message);
    } else if (err.status === 500) {
        this.dialog.open(ErrorDialogComponent, {
          width: '750px',
          data: {title:'Ошибка', message:err.error}
        });
    }
    return throwError(err);
  }

}
