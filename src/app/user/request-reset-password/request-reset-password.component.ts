import { Component, OnInit } from '@angular/core';
import { FormBuilder, FormGroup, Validators } from '@angular/forms';
import { AuthService } from 'src/app/services/auth.service';
import { MatSnackBar } from '@angular/material/snack-bar';
import { Router } from '@angular/router';

@Component({
  selector: 'app-request-reset-password',
  templateUrl: './request-reset-password.component.html',
  styleUrls: ['./request-reset-password.component.css']
})
export class RequestResetPasswordComponent implements OnInit {
  public requestResetForm: FormGroup;

  constructor(
    private _fb: FormBuilder,
    private _authService: AuthService,
    private _snackBar: MatSnackBar,
    private _router: Router
  ) { }

  ngOnInit() {
    this.requestResetForm = this._fb.group({
      email: [null, [Validators.email, Validators.required]]
    });
  }

  requestResetUserPwd() {
    // console.log(this.requestResetForm);
    this._authService.requestReset(this.requestResetForm.value.email).subscribe(
      (res) => {
        if (res.isUserExist) {
          this.requestResetForm.reset();
          setTimeout(() => {
            this._router.navigate(["login"]);
          }, 3000);
        }
        this._snackBar.open(res.msg, "", { duration: 3000 });
      },
      (error) => {
        this._snackBar.open("ERROR: In while resetting password", "", { duration: 3000 });
        console.error(error);
      }
    );
  }

}
