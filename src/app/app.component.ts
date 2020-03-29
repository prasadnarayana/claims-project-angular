import { Component } from '@angular/core';
import { AuthService } from './services/auth.service';
import { Router } from '@angular/router';

@Component({
  selector: 'app-root',
  templateUrl: './app.component.html',
  styleUrls: ['./app.component.css']
})
export class AppComponent {
  title = 'Claims Project';

  constructor(
    private _authService: AuthService,
    private _router: Router
  ) { }

  logout() {
    this._authService.logout();
    this._router.navigate(["login"]);
  }
}
