import { Component, OnInit, Inject } from '@angular/core';
import { MatDialogRef, MAT_DIALOG_DATA, MatSnackBar } from '@angular/material';
import { UserHomeComponent } from '../user-home/user-home.component';
import { UserService } from 'src/app/services/user.service';

@Component({
  selector: 'app-activity-history',
  templateUrl: './activity-history.component.html',
  styleUrls: ['./activity-history.component.css']
})
export class ActivityHistoryComponent implements OnInit {
  public displayColumns: string[] = ["actionPerformed", "timestamp"];
  public dataSource;

  constructor(
    public _dialogRef: MatDialogRef<UserHomeComponent>,
    @Inject(MAT_DIALOG_DATA) public _data: any,
    private _userService: UserService,
    private _snackBar: MatSnackBar
  ) { }

  ngOnInit() {
    this.getHistory();
  }

  getHistory() {
    this._userService.getActionHistory(this._data.id).subscribe(
      actions => {
        // console.log(actions);
        this.dataSource = actions;
      },
      error => {
        this._snackBar.open("ERROR: In selecting action history", "", { duration: 3000 });
        console.error(error);
      }
    );
  }

  closeDialog(): void {
    this._dialogRef.close();
  }

}
