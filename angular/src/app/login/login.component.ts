import { Component, OnInit } from '@angular/core';
import {FormBuilder, FormGroup, Validators} from "@angular/forms";
import {Router} from "@angular/router";
import {first} from "rxjs/operators";
import {AuthService} from "../_service/auth.service";

@Component({
  selector: 'app-login',
  templateUrl: './login.component.html',
  styleUrls: ['./login.component.scss']
})
export class LoginComponent implements OnInit {
  loginForm: FormGroup;
  loading = false;
  submitted = false;

  constructor(
    private formBuilder: FormBuilder,
    private router: Router,
    private _authService:AuthService
  ) {
    _authService.getCurrentUser()
      .pipe()
      .subscribe(res => {
        if (res) {
          router.navigateByUrl('/room');
        }
      })
  }

  ngOnInit(): void {
    this.loginForm = this.formBuilder.group({
      login: ['', Validators.required],
      password: ['', Validators.required]
    })
  }

  get f() {
    return this.loginForm.controls;
  }

  onSubmit() {
    this.submitted = true;

    if (this.loginForm.invalid){
      return;
    }

    this.loading = true;
    this._authService.login(this.f.login.value, this.f.password.value)
      .pipe(first())
      .subscribe(() => this.router.navigateByUrl('/room'), () => this.loading = false);
  }

}
