import {CourseList} from "./course-list";

export class Teacher {
  idd:number;
  firstName:string;
  middleName:string;
  lastName:string;
  passport:string;
  status:string;
  birthDate:string;
  createDate:string;
  history:[];
  courses: CourseList[];
}
