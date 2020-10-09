import { Injectable } from '@angular/core';
import {HttpClient} from "@angular/common/http";
import {Observable} from "rxjs";

@Injectable({
  providedIn: 'root'
})
export class AuthService {

  constructor(private _httpClient:HttpClient) { }

  public getCurrentUser() {
    return this._httpClient.get('/api/auth/current')
  }

  public login(login: String, password:String):Observable<Object>{
    return this._httpClient.post('/api/auth/login', {login:login, password:password})
  }

  //todo ДЗ logout
  public logout():Observable<Object> {
    return this._httpClient.get('/api/auth/logout')
  }
}
