import { BrowserModule } from '@angular/platform-browser';
import { NgModule } from '@angular/core';
import { BrowserAnimationsModule } from '@angular/platform-browser/animations';

// External Modules
import { ReactiveFormsModule, FormsModule } from '@angular/forms';
import { JwtModule } from '@auth0/angular-jwt';

// Angular Meterial Modules
import { MatToolbarModule } from '@angular/material/toolbar';
import { MatListModule } from '@angular/material/list';
import { MatButtonModule } from '@angular/material/button';
import { MatGridListModule } from '@angular/material/grid-list';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatInputModule } from '@angular/material/input';
import { MatSnackBarModule } from '@angular/material/snack-bar';
import { MatTableModule } from '@angular/material/table';
import { MatDatepickerModule } from '@angular/material/datepicker';
import { MatNativeDateModule } from '@angular/material/core';
import { MatCardModule } from '@angular/material/card';
import { MatSelectModule } from '@angular/material/select';
import { MatBottomSheetModule } from '@angular/material/bottom-sheet';
import { MatRadioModule } from '@angular/material/radio';
import { MatSidenavModule } from '@angular/material/sidenav';
import { MatPaginatorModule } from '@angular/material/paginator';
import { MatIconModule } from '@angular/material/icon';
import { MatDialogModule } from '@angular/material/dialog';

// Components
import { AppRoutingModule } from './app-routing.module';
import { AppComponent } from './app.component';
import { RegisterComponent } from './user/register/register.component';
import { LoginComponent } from './user/login/login.component';
import { UserHomeComponent } from './user/user-home/user-home.component';
import { PageNotFoundComponent } from './page-not-found/page-not-found.component';
import { HeaderComponent } from './layout/header/header.component';
import { FooterComponent } from './layout/footer/footer.component';
import { ClaimsFormComponent } from './user/claims-form/claims-form.component';

// Services
import { AuthService } from './services/auth.service';
import { HttpClientModule } from '@angular/common/http';

// Guards
import { AuthGuard } from './guards/auth.guard';
import { AccessDeniedComponent } from './access-denied/access-denied.component';
import { AdminHomeComponent } from './admin/admin-home/admin-home.component';
import { ClaimsComponent } from './admin/claims/claims.component';
import { AddUserComponent } from './admin/add-user/add-user.component';
import { RemoveUserComponent } from './admin/remove-user/remove-user.component';
import { DeleteConfirmPopupComponent } from './user/delete-confirm-popup/delete-confirm-popup.component';
import { ActivityHistoryComponent } from './user/activity-history/activity-history.component';
import { RequestResetPasswordComponent } from './user/request-reset-password/request-reset-password.component';
import { ResponseResetPasswordComponent } from './user/response-reset-password/response-reset-password.component';

export function tokenGetter() {
  return localStorage.getItem('access_token');
}

@NgModule({
  declarations: [
    AppComponent,
    RegisterComponent,
    LoginComponent,
    UserHomeComponent,
    PageNotFoundComponent,
    HeaderComponent,
    FooterComponent,
    ClaimsFormComponent,
    AccessDeniedComponent,
    AdminHomeComponent,
    ClaimsComponent,
    AddUserComponent,
    RemoveUserComponent,
    DeleteConfirmPopupComponent,
    ActivityHistoryComponent,
    RequestResetPasswordComponent,
    ResponseResetPasswordComponent
  ],
  entryComponents: [
    ClaimsFormComponent,
    DeleteConfirmPopupComponent,
    ActivityHistoryComponent
  ],
  imports: [
    BrowserModule,
    AppRoutingModule,
    FormsModule,
    ReactiveFormsModule,
    HttpClientModule,
    BrowserAnimationsModule,
    JwtModule.forRoot({
      config: {
        tokenGetter: tokenGetter,
        whitelistedDomains: [

        ],
        blacklistedRoutes: [
          "http://localhost:5000/auth/register",
          "http://localhost:5000/auth/login"
        ]
      }
    }),
    MatToolbarModule,
    MatListModule,
    MatButtonModule,
    MatGridListModule,
    MatFormFieldModule,
    MatInputModule,
    MatSnackBarModule,
    MatTableModule,
    MatDatepickerModule,
    MatNativeDateModule,
    MatCardModule,
    MatSelectModule,
    MatBottomSheetModule,
    MatRadioModule,
    MatSidenavModule,
    MatPaginatorModule,
    MatIconModule,
    MatDialogModule
  ],
  providers: [
    AuthService,
    AuthGuard
  ],
  bootstrap: [AppComponent]
})
export class AppModule { }
