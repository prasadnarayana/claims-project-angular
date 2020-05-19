import { Component, OnInit } from '@angular/core';
import { FormGroup, Validators, FormBuilder } from '@angular/forms';
import { AuthService } from 'src/app/services/auth.service';
import { MatSnackBar } from '@angular/material/snack-bar';
import { Router, ActivatedRoute } from '@angular/router';

@Component({
  selector: 'app-response-reset-password',
  templateUrl: './response-reset-password.component.html',
  styleUrls: ['./response-reset-password.component.css']
})
export class ResponseResetPasswordComponent implements OnInit {
  public responseResetForm: FormGroup;
  public resetToken: null;
  public currentState: any;

  constructor(
    private _fb: FormBuilder,
    private _authService: AuthService,
    private _snackBar: MatSnackBar,
    private _router: Router,
    private _route: ActivatedRoute
  ) {
    this.currentState = "Wait";
    this._route.params.subscribe(params => {
      this.resetToken = params.token;
      console.log(this.resetToken);
      this.verifyToken();
    });
  }

  ngOnInit() {
    this.init();
  }

  verifyToken() {
    this._authService.validPasswordToken(this.resetToken).subscribe(
      (res) => {
        // console.log(res);
        if (res.success) {
          this.currentState = "Verified";
        } else {
          this.currentState = "NotVerified";
        }
      },
      (error) => {
        this._snackBar.open("ERROR: In verifying token", "", { duration: 3000 });
        console.error(error);
        this.currentState = "NotVerified";
      }
    );
  }

  init() {
    this.responseResetForm = this._fb.group({
      resettoken: [this.resetToken],
      newPassword: ['', [Validators.required]],
      confirmPassword: ['', [Validators.required]]
    });
  }

  resetPassword() {
    const data = {
      newPassword: this.responseResetForm.value.newPassword,
      resetToken: this.resetToken
    }

    this._authService.newPassword(data).subscribe(
      (res) => {
        if (res.success) {
          this.responseResetForm.reset();
          this._snackBar.open(res.msg, "", { duration: 3000 });
          setTimeout(() => {
            this._router.navigate(["login"]);
          }, 3000);
        } else {
          this._snackBar.open(res.msg, "", { duration: 3000 });
        }
      },
      (error) => {
        this._snackBar.open("ERROR: In updating password", "", { duration: 3000 });
        console.error(error);
      }
    );
  }

}
