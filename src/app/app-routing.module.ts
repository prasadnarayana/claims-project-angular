import { NgModule } from '@angular/core';
import { Routes, RouterModule } from '@angular/router';
import { RegisterComponent } from './user/register/register.component';
import { LoginComponent } from './user/login/login.component';
import { UserHomeComponent } from './user/user-home/user-home.component';
import { PageNotFoundComponent } from './page-not-found/page-not-found.component';
import { AuthGuard } from './guards/auth.guard';
import { AccessDeniedComponent } from './access-denied/access-denied.component';
import { AdminHomeComponent } from './admin/admin-home/admin-home.component';
import { ClaimsComponent } from './admin/claims/claims.component';
import { AddUserComponent } from './admin/add-user/add-user.component';
import { RemoveUserComponent } from './admin/remove-user/remove-user.component';

const routes: Routes = [
  {
    path: "register",
    component: RegisterComponent
  },
  {
    path: "login",
    component: LoginComponent
  },
  {
    path: "user",
    component: UserHomeComponent,
    data: {
      allowedRole: "user"
    },
    canActivate: [
      AuthGuard
    ]
  },
  {
    path: "admin",
    component: AdminHomeComponent,
    data: {
      allowedRole: "admin"
    },
    canActivate: [
      AuthGuard
    ],
    children: [
      { path: "", component: ClaimsComponent },
      { path: "adduser", component: AddUserComponent },
      { path: "removeuser", component: RemoveUserComponent }
    ]
  },
  {
    path: "accessdenied",
    component: AccessDeniedComponent
  },
  {
    path: "",
    redirectTo: "/login",
    pathMatch: "full"
  },
  {
    path: '**',
    component: PageNotFoundComponent
  }
];

@NgModule({
  imports: [RouterModule.forRoot(routes)],
  exports: [RouterModule]
})
export class AppRoutingModule { }
