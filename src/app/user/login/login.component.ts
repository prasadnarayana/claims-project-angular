import { Component, OnInit } from '@angular/core';
import { FormGroup, Validators, FormBuilder } from '@angular/forms';
import { AuthService } from 'src/app/services/auth.service';
import { MatSnackBar } from '@angular/material/snack-bar';
import { Router } from '@angular/router';

@Component({
  selector: 'app-login',
  templateUrl: './login.component.html',
  styleUrls: ['./login.component.css']
})
export class LoginComponent implements OnInit {
  public loginForm: FormGroup;

  constructor(
    private _fb: FormBuilder,
    private _authService: AuthService,
    private _snackBar: MatSnackBar,
    private _router: Router
  ) { }

  ngOnInit() {
    this.loginForm = this._fb.group({
      role: ["user"],
      email: [null, [Validators.email, Validators.required]],
      password: [null, [Validators.required]]
    });
  }

  onLoginFormSubmit() {
    const userCredentials = {
      role: this.loginForm.value.role,
      email: this.loginForm.value.email,
      password: this.loginForm.value.password
    }

    this._authService.signIn(userCredentials).subscribe(
      (res) => {
        if(res.isLoggedIn) {
          localStorage.setItem("access_token", res.token);
          
          if (userCredentials.role === "user")
            this._router.navigate(["user"]);
          else
            this._router.navigate(["admin"]);
        } else {
          this._snackBar.open(res.msg, "", { duration: 3000 });
        }
      },
      (error) => {
        this._snackBar.open("ERROR: In connecting to the server", "", { duration: 3000 });
        console.error(error);
      }
    );
  }

}
