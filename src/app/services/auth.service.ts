import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable } from 'rxjs';
import { Credentials } from '../interfaces/credentials';
import { JwtHelperService } from '@auth0/angular-jwt';

@Injectable({
  providedIn: 'root'
})
export class AuthService {
  readonly baseURL: string = "http://localhost:5000/auth/";

  constructor(
    private _http: HttpClient,
    private _jwtHelperService: JwtHelperService,
  ) { }

  signUp(newUser: Credentials): Observable<any> {
    return this._http.post(this.baseURL + "register", newUser);
  }

  signIn(userCredentials: Credentials): Observable<any> {
    return this._http.post<{ token: string }>(this.baseURL + "signin", userCredentials);
  }

  requestReset(email): Observable<any> {
    return this._http.post(this.baseURL + "request-reset-password", { email });
  }

  newPassword(data): Observable<any> {
    return this._http.post(this.baseURL + "new-password", data);
  }

  validPasswordToken(resetToken): Observable<any> {
    return this._http.post(this.baseURL + "valid-password-token", { resetToken });
  }

  logout() {
    localStorage.removeItem('access_token');
  }

  public get loggedIn(): boolean {
    return (localStorage.getItem('access_token') !== null);
  }

  public get currentUser(): string {
    try {
      let tokenInfo = this._jwtHelperService.decodeToken(localStorage.getItem('access_token'));
      return tokenInfo.user;
    } catch(error){
      console.log(error);
    }
  }
}
