import {StudentList} from "./student-list";

export class Course {
  idd:number;
  name:string;
  description:string;
  maxCountStudent:number;
  status:string;
  startDate:string;
  endDate:string;
  createDate:string;
  history:[];
  students:StudentList[];
}
