import {InstrumentList} from "./instrument-list";

export class Lesson {
  idd:number;
  name:string;
  description:string;
  lessonDateStart:string;
  lessonDateEnd:string;
  extraInstruments:string;
  history:[];
  instruments:InstrumentList[];
}
