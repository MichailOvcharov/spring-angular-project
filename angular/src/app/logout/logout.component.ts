import { Component, OnInit } from '@angular/core';
import {AuthService} from "../_service/auth.service";
import {Router} from "@angular/router";

@Component({
  selector: 'app-logout',
  templateUrl: './logout.component.html',
  styleUrls: ['./logout.component.scss']
})
export class LogoutComponent implements OnInit {

  constructor(private _authService:AuthService, public router: Router) {}

  ngOnInit(): void {
  }

  onClick(): void {
    this._authService.logout()
      .pipe()
      .subscribe(res => {
        this.router.navigateByUrl('/login');
      });
  }

}
