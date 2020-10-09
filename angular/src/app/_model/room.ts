import {InstrumentList} from "./instrument-list";

export class Room {
  idd:number;
  number:string;
  block:string;
  createDate:string;
  history:[];
  instruments:InstrumentList[];
}
