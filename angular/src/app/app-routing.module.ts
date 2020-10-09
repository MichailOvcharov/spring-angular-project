import { NgModule } from '@angular/core';
import { Routes, RouterModule } from '@angular/router';
import {RoomComponent} from "./room/room.component";
import {InstrumentComponent} from "./instrument/instrument.component";
import {StudentComponent} from "./student/student.component";
import {CourseComponent} from "./course/course.component";
import {TeacherComponent} from "./teacher/teacher.component";
import {LessonComponent} from "./lesson/lesson.component";
import {LoginComponent} from "./login/login.component";


const routes: Routes = [
  {path:'room', component:RoomComponent},
  {path:'instrument', component:InstrumentComponent},
  {path:'student', component:StudentComponent},
  {path:'course', component:CourseComponent},
  {path:'teacher', component:TeacherComponent},
  {path:'lesson', component:LessonComponent},
  {path:'login', component:LoginComponent},

  // {path:'**', redirectTo:'/room'}
  {path:'**', redirectTo:'/login'}
];

@NgModule({
  imports: [RouterModule.forRoot(routes)],
  exports: [RouterModule]
})
export class AppRoutingModule { }
export const routingComponents = [RoomComponent,InstrumentComponent, StudentComponent, CourseComponent, TeacherComponent, LessonComponent];
