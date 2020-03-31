import { Component, OnInit } from '@angular/core';
import { FormGroup, FormBuilder, Validators } from '@angular/forms';
import { MatBottomSheet } from '@angular/material';
import { ClaimsFormComponent } from '../claims-form/claims-form.component';

const CLAIMS_DATA: any[] = [
  {policyNo: 1, name: "Prasad Babu", totalExpenses: 100, currentStatus: "Pending"},
  {policyNo: 2, name: "Manikanta", totalExpenses: 400, currentStatus: "Aproved"},
  {policyNo: 3, name: "Ravi Kiran", totalExpenses: 600, currentStatus: "Aproved"},
];

@Component({
  selector: 'app-user-home',
  templateUrl: './user-home.component.html',
  styleUrls: ['./user-home.component.css']
})
export class UserHomeComponent implements OnInit {
  public displayColumns: string[] = ["policyNo", "name", "totalExpenses", "currentStatus", "action"];
  public dataSource = CLAIMS_DATA;
  public searchForm: FormGroup;

  constructor(
    private _fb: FormBuilder,
    private _bottomSheet: MatBottomSheet
  ) { }

  ngOnInit() {
    this.searchForm = this._fb.group({
      email: [null, [Validators.email, Validators.required]]
    });
  }

  openClaimsForm(policyNo): void {
    this._bottomSheet.open(ClaimsFormComponent, {
      data: { policyNo }
    });
  }

}
