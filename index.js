const express = require("express");
const mysql = require("mysql");
const cors = require("cors");
const app = express();
// const csvtojson = require("csvtojson"); // 맨 위에 선언
// const multer = require('multer');
// const upload = require('./fileupload');
// const path = require("path");
// const fs = require("fs");
const jwt = require("jsonwebtoken");
const secretObj = require("./config/jwt");
const bcrypt = require("bcryptjs");

app.use(express.urlencoded({ extended: true }))

app.use(express.json());
app.use(cors());

// 서버를 3001 포트로 연결
app.listen(3001, () => {
  console.log("running server");
});

// 서버 접속
const db = mysql.createConnection({
  user: "root",
  host: "127.0.0.1",
  password: "root",
  database: "vompms",
});

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

// 회원가입 등록
app.post("/register", (req, res) => {
  const id = req.body.id;
  const password = req.body.password;
  const name = req.body.name;

  bcrypt.hash(password, 10, (err, hash) => {
    if (err) {
      res.send({
        success: false,
        message: "암호화 실패",
      })
    } else {
      db.query(
        "SELECT * FROM member WHERE id = ?",
        [id],
        (err, result) => {
          if (err) {
            res.send({
              success: false,
              message: "아이디 중복 체크 실패",
            });
          } else {
            if (result.length > 0) {
              res.send({
                success: false,
                message: "이미 존재하는 아이디입니다.",
              });
            } else {
              db.query(
                "INSERT INTO member (id,password,name) VALUES (?,?,?)", //SQL 문
                [id, hash, name],
                (err, result) => {
                  if (err) {
                    res.send({
                      success: false,
                      message: "회원가입 실패",
                    });
                  } else {
                    res.send({
                      success: true,
                      message: "회원가입 성공",
                    });
                  }
                }
              );
            }
          }
        }
      );
    }
  });
});

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

// 로그인
app.post("/login", (req, res) => {
  const id = req.body.loginInfo.id;
  const password = req.body.loginInfo.password;
  
  db.query(
    "SELECT * FROM member WHERE id = ? ",
    [id],
    (error, result) => {
      if (error) {
        console.log(error);
      } else {
        if (result.length === 0) {
          res.send({
            result: "fail",
            message: "아이디가 존재하지 않습니다.",
          });
        } else {
          const token = jwt.sign({ id: id, authority: result[0].authority }, secretObj.secret, { expiresIn: '1d' });
          const hashedPassword = result[0].password;
          const name = result[0].name;
          const authority = result[0].authority;
          bcrypt.compare(password, hashedPassword, (err, result) => {
            if (err) {
              console.log(err);
            } else {
              if (result && (authority == 0 || authority == 1 || authority == 2)) {
                res.send({
                  result: "success",
                  token: token,
                  id: id,
                  name: name,
                  authority: authority,
                });
              } else if (result) {
                res.send({
                  result: "fail",
                  message: "접근 권한이 없습니다.",
                });
              } else {
                res.send({
                  result: "fail",
                  message: "비밀번호가 일치하지 않습니다.",
                });
              }
            }
          });
        }
      }
    }
  );
});

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

// 관리자 페이지

// 1. 멤버

// 1-1. 관리자 페이지 멤버 데이터 로드
app.get("/members", (req, res) => {
  const token = req.headers.authorization;
  try {
    const decoded = jwt.verify(token, secretObj.secret);
    db.query("SELECT * FROM member", (err, rows, fields) => {
      if (err) console.log(err);
      res.send(rows);
    });
  } catch (error) {
    res.sendStatus(401);
  }
});

// 1-1-1. 멤버 개인 정보 로드
app.get('/members/search',(req,res)=>{
  const id = req.query.id;
  const token = req.headers.authorization;
  try {
    const decoded = jwt.verify(token, secretObj.secret);
    if (decoded.id != id) {
      res.sendStatus(401);
    } else {
      db.query("SELECT * FROM member WHERE id = ? ", 
      [id], 
      (err, rows, fields) => {
        if (err) console.log(err);
        res.send(rows);
      });
    }
  } catch (error) {
    res.sendStatus(401);
  }
})

// 1-2. 관리자 페이지 멤버 데이터 추가
app.post("/members/add", (req, res) => {
  const id = req.body.member.id;
  const name = req.body.member.name;
  const 소속 = req.body.member.소속;
  const team = req.body.member.team;
  const 직급 = req.body.member.직급;
  const 직책 = req.body.member.직책;
  const authority = req.body.member.authority;
  const token = req.headers.authorization;
  try {
    const decoded = jwt.verify(token, secretObj.secret);
    bcrypt.hash('1234', 10, (err, hash) => {
      if (err) {
        res.send({
          success: false,
          message: "암호화 실패",
        })
      } else {
        db.query(
          "SELECT * FROM member WHERE id = ?",
          [id],
          (err, result) => {
            if (err) {
              res.send({
                success: false,
                message: "아이디 중복 체크 실패",
              });
            } else {
              if (result.length > 0) {
                res.send({
                  success: false,
                  message: "이미 존재하는 아이디입니다.",
                });
              } else {
                db.query(
                  "INSERT INTO member (id,name,password,소속,team,직급, 직책, authority) VALUES (?,?,?,?,?,?,?,?)", //SQL 문
                  [id, name, hash, 소속, team, 직급, 직책, authority],
                  (err, result) => {
                    if (err) {
                      res.send({
                        success: false,
                        message: "멤버 추가 실패",
                      });
                    } else {
                      res.send({
                        success: true,
                        message: "",
                      });
                    }
                  }
                );
              }
            }
          }
        );
      }
    });
  } catch (error) {
    res.sendStatus(401);
  }
});

// 1-3. 관리자 페이지 멤버 데이터 수정
app.post("/members/update", (req, res) => {
  const num = req.body.member.num;
  const id = req.body.member.id;
  const password = req.body.member.password;
  const name = req.body.member.name;
  const 소속 = req.body.member.소속;
  const team = req.body.member.team;
  const 직급 = req.body.member.직급;
  const 직책 = req.body.member.직책;
  const authority = req.body.member.authority;
  const token = req.headers.authorization;
  try {
    const decoded = jwt.verify(token, secretObj.secret);
    db.query(
      "UPDATE member SET id = ? , password = ? , name = ? , 소속 =?, team = ?, 직급=? , 직책 =?, authority =? WHERE num = ?", //SQL 문
      [id, password, name, 소속, team, 직급, 직책, authority, num],
      (err, result) => {
        if (err) console.log(err);
      }
    );
  } catch (error) {
    res.sendStatus(401);
  }
});

// 1-4. 관리자 페이지 멤버 데이터 삭제
app.post("/members/delete", (req, res) => {
  const num = req.body.num;
  const token = req.headers.authorization;
  try {
    const decoded = jwt.verify(token, secretObj.secret);
    db.query(
      "DELETE FROM member WHERE num= ?", //SQL 문
      [num],
      (err, result) => {
        if (err) console.log(err);
      }
    );
  } catch (error) {
    res.sendStatus(401);
  }
});

// 1-5. 멤버 비밀번호 변경
app.post("/members/password", (req, res) => {
  const num = req.body.num;
  const password = req.body.password;
  const token = req.headers.authorization;
  try {
    const decoded = jwt.verify(token, secretObj.secret);
    bcrypt.hash(password, 10, (err, hash) => {
      db.query(
        "UPDATE member SET password = ? WHERE num = ?", //SQL 문
        [hash, num],
        (err, result) => {
          if (err) console.log(err);
        }
      );
    });
  } catch (error) {
    res.sendStatus(401);
  }
});


// 2. 팀

// 2-1. 관리자 페이지 팀 데이터 로드
app.get("/teams", (req, res) => {
  const token = req.headers.authorization;
  try {
    const decoded = jwt.verify(token, secretObj.secret);
    db.query("SELECT * FROM team", (err, rows, fields) => {
      if (err) console.log(err);
      res.send(rows);
    });
  } catch (error) {
    res.sendStatus(401);
  }
});

// 2-2. 관리자 페이지 팀 데이터 추가
app.post("/teams/add", (req, res) => {
  const num = req.body.team.num;
  const teamname = req.body.team.teamname;
  const firstorder = req.body.team.firstorder;
  const firstsale = req.body.team.firstsale;
  const lastorder = req.body.team.lastorder;
  const lastsale = req.body.team.lastsale;
  const year = req.body.team.year;
  const token = req.headers.authorization;
  try {
    const decoded = jwt.verify(token, secretObj.secret);
    db.query(
      "INSERT INTO team ( num, teamname, firstorder, firstsale, lastorder, lastsale, year) VALUES (?,?,?,?,?,?,?)", //SQL 문
      [num, teamname, firstorder, firstsale, lastorder, lastsale, year],
      (err, result) => {
        if (err) console.log(err);
      }
    );
  } catch (error) {
    res.sendStatus(401);
  }
});

// 2-3. 관리자 페이지 팀 데이터 수정
app.post("/teams/update", (req, res) => {
  const num = req.body.team.num;
  const teamname = req.body.team.teamname;
  const firstorder = req.body.team.firstorder;
  const firstsale = req.body.team.firstsale;
  const lastorder = req.body.team.lastorder;
  const lastsale = req.body.team.lastsale;
  const year = req.body.team.year;
  const token = req.headers.authorization;
  try {
    const decoded = jwt.verify(token, secretObj.secret);
    db.query(
      "UPDATE team SET teamname = ? , firstorder = ? , firstsale = ?, lastorder = ? , lastsale = ? WHERE num = ? and year = ?", //SQL 문
      [teamname, firstorder, firstsale, lastorder, lastsale, num, year],
      (err, result) => {
        if (err) console.log(err);
      }
    );
  } catch (error) {
    res.sendStatus(401);
  }
});

// 2-4. 관리자 페이지 팀 데이터 삭제
app.post("/teams/delete", (req, res) => {
  const teamname = req.body.teamname;
  const year = req.body.year;
  const token = req.headers.authorization;
  try {
    const decoded = jwt.verify(token, secretObj.secret);
    db.query(
      "DELETE FROM team WHERE teamname=? and year=?", //SQL 문
      [teamname, year],
      (err, result) => {
        if (err) console.log(err);
      }
    );
  } catch (error) {
    res.sendStatus(401);
  }
});

// 2-5. 관리자 페이지 팀 데이터 순서 변경
app.post("/teams/order", (req, res) => {
  const teams = req.body.teams;
  const token = req.headers.authorization;
  teams.forEach((team) => {
    const teamname = team.teamname;
    const year = team.year;
    const num = team.num;
    try {
      const decoded = jwt.verify(token, secretObj.secret);
      db.query(
        "UPDATE team SET num = ? WHERE teamname = ? and year = ?", //SQL 문
        [num, teamname, year],
        (err, result) => {
          if (err) console.log(err);
        }
      );
    } catch (error) {
      res.sendStatus(401);
    }
  });
});

// 3. 툴

// 3-1. 관리자 페이지 툴 데이터 로드
app.get("/tools", (req, res) => {
  const token = req.headers.authorization;
  try {
    const decoded = jwt.verify(token, secretObj.secret);
    db.query("SELECT * FROM tool", (err, rows, fields) => {
      if (err) console.log(err);
      res.send(rows);
    });
  } catch (error) {
    res.sendStatus(401);
  }
});

// 3-2. 관리자 페이지 툴 데이터 추가
app.post("/tools/add", (req, res) => {
  const num = req.body.num;
  const toolname = req.body.toolname;
  const token = req.headers.authorization;
  try {
    const decoded = jwt.verify(token, secretObj.secret);
    db.query(
      "INSERT INTO tool (num,toolname) VALUES (?,?)", //SQL 문
      [num, toolname],
      (err, result) => {
        if (err) console.log(err);
      }
    );
  } catch (error) {
    res.sendStatus(401);
  }
});

// 3-3. 관리자 페이지 툴 데이터 수정
app.post("/tools/update", (req, res) => {
  const num = req.body.num;
  const toolname = req.body.toolname;
  const token = req.headers.authorization;
  try {
    const decoded = jwt.verify(token, secretObj.secret);
    db.query(
      "UPDATE tool SET  toolname = ? WHERE num = ?", //SQL 문
      [toolname, num],
      (err, result) => {
        if (err) console.log(err);
      }
    );
  } catch (error) {
    res.sendStatus(401);
  }
});

// 3-4. 관리자 페이지 툴 데이터 삭제
app.post("/tools/delete", (req, res) => {
  const num = req.body.num;
  const token = req.headers.authorization;
  try {
    const decoded = jwt.verify(token, secretObj.secret);
    db.query(
      "DELETE FROM tool WHERE num= ?", //SQL 문
      [num],
      (err, result) => {
        if (err) console.log(err);
      }
    );
  } catch (error) {
    res.sendStatus(401);
  }
});

// 4. 근무지

// 4-1. 관리자 페이지 근무지 데이터 로드
app.get("/places", (req, res) => {
  const token = req.headers.authorization;
  try {
    const decoded = jwt.verify(token, secretObj.secret);
    db.query("SELECT * FROM work_place", (err, rows, fields) => {
      if (err) console.log(err);
      res.send(rows);
    });
  } catch (error) {
    res.sendStatus(401);
  }
});

// 4-2. 관리자 페이지 근무지 데이터 추가
app.post("/places/add", (req, res) => {
  const num = req.body.num;
  const name = req.body.name;
  const color = req.body.color;
  const year = req.body.year;
  const token = req.headers.authorization;
  try {
    const decoded = jwt.verify(token, secretObj.secret);
    db.query(
      "INSERT INTO work_place (num,name,color,year) VALUES (?,?,?,?)", //SQL 문
      [num, name, color, year],
      (err, result) => {
        if (err) console.log(err);
      }
    );
  } catch (error) {
    res.sendStatus(401);
  }
});

// 4-3. 관리자 페이지 근무지 데이터 수정
app.post("/places/update", (req, res) => {
  const num = req.body.place.num;
  const name = req.body.place.name;
  const color = req.body.place.color;
  const year = req.body.place.year;
  const token = req.headers.authorization;
  try {
    const decoded = jwt.verify(token, secretObj.secret);
    db.query(
      "UPDATE work_place SET  name = ?, color = ? WHERE num = ? and year = ? ", //SQL 문
      [name, color, num, year],
      (err, result) => {
        if (err) console.log(err);
      }
    );
  } catch (error) {
    res.sendStatus(401);
  }
});

// 4-4. 관리자 페이지 근무지 데이터 삭제
app.post("/places/delete", (req, res) => {
  const name = req.body.name;
  const year = req.body.year;
  const token = req.headers.authorization;
  try {
    const decoded = jwt.verify(token, secretObj.secret);
    db.query(
      "DELETE FROM work_place WHERE name= ? and year = ?", //SQL 문
      [name, year],
      (err, result) => {
        if (err) console.log(err);
      }
    );
  } catch (error) {
    res.sendStatus(401);
  }
});

// 4-5. 관리자 페이지 근무지 데이터 순서 변경
app.post("/places/order", (req, res) => {
  const places = req.body.places;
  const token = req.headers.authorization;
  places.forEach((place) => {
    const num = place.num;
    const name = place.name;
    const year = place.year;
    try {
      const decoded = jwt.verify(token, secretObj.secret);
      db.query(
        "UPDATE work_place SET num=? WHERE name = ? and year = ? ", //SQL 문
        [num, name, year],
        (err, result) => {
          if (err) console.log(err);
        }
      );
    } catch (error) {
      res.sendStatus(401);
    }
  });
});

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

// 프로젝트

// 1. 프로젝트 - 목록

// 1-1. 프로젝트 DB 불러오기
app.get('/projects',(req,res)=>{
  const token = req.headers.authorization;
  try {
    const decoded = jwt.verify(token, secretObj.secret);
    db.query(
        "SELECT * FROM project",
        (err,rows,fields)=>{
            res.send(rows);
        }
    );
  } catch (error) {
    res.sendStatus(401);
  }
})

// 1-2. id, year 값 맞는 프로젝트 찾기
app.get('/projects/search',(req,res)=>{
  const id = req.query.id
  const year = req.query.year
  const query = "SELECT * FROM project WHERE id = '"+id+"' and year = '" + year + "'"
  const token = req.headers.authorization;
  try {
    const decoded = jwt.verify(token, secretObj.secret);
    db.query(
      query,
      (err,rows,fields)=>{
        res.send(rows);
        console.log(err);
      }
    );
  } catch (error) {
    res.sendStatus(401);
  }
})

// 1-3. 프로젝트 추가
app.post("/projects/add", (req, res) =>{
  const 팀수주 = req.body.project.팀수주
  const 팀매출 = req.body.project.팀매출
  const 프로젝트코드 = req.body.project.프로젝트코드
  const 프로젝트명 = req.body.project.프로젝트명
  const 상태 = req.body.project.상태
  const 실 = req.body.project.실
  const 고객사 = req.body.project.고객사
  const 고객부서 = req.body.project.고객부서
  const ManMonth = req.body.project.ManMonth
  const 프로젝트계약금액_백만 = req.body.project.프로젝트계약금액_백만
  const 상반기예상수주 = req.body.project.상반기예상수주
  const 상반기수주 = req.body.project.상반기수주
  const 상반기예상매출 = req.body.project.상반기예상매출
  const 상반기매출 = req.body.project.상반기매출
  const 하반기예상수주 = req.body.project.하반기예상수주
  const 하반기수주 = req.body.project.하반기수주
  const 하반기예상매출 = req.body.project.하반기예상매출
  const 하반기매출 = req.body.project.하반기매출
  const 장비비 = req.body.project.장비비
  const 컨설팅비 = req.body.project.컨설팅비
  const 도구비 = req.body.project.도구비
  const 착수 = req.body.project.착수
  const 종료 = req.body.project.종료
  const 고객담당자 = req.body.project.고객담당자
  const 근무지 = req.body.project.근무지
  const 업무 = req.body.project.업무
  const 도구 = req.body.project.도구
  const 과제성격 = req.body.project.과제성격
  const 사업지역 = req.body.project.사업지역
  const PM = req.body.project.PM
  const 투입명단 = req.body.project.투입명단
  const 주간보고서 = req.body.project.주간보고서
  const 실적보고 = req.body.project.실적보고
  const year = req.body.project.year
  const token = req.headers.authorization;
  try {
    const decoded = jwt.verify(token, secretObj.secret);
    db.query(
      "SElECT id FROM project WHERE 프로젝트명 = '"+프로젝트명+"' AND year != '"+year+"' LIMIT 1",
      (err,rows,fields)=>{
        if(rows.length == 0){
          db.query(
            "INSERT INTO project ( 팀수주,팀매출,프로젝트코드,프로젝트명,상태,실,고객사,고객부서,ManMonth,프로젝트계약금액_백만,상반기예상수주, 상반기수주, 상반기예상매출, 상반기매출, 하반기예상수주, 하반기수주, 하반기예상매출, 하반기매출, 장비비, 컨설팅비, 도구비, 착수, 종료, 고객담당자, 근무지, 업무, 도구, 과제성격, 사업지역, PM, 투입명단, 주간보고서, 실적보고, year) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", //SQL 문 
            [팀수주,팀매출,프로젝트코드,프로젝트명,상태,실,고객사,고객부서,ManMonth,프로젝트계약금액_백만,상반기예상수주, 상반기수주, 상반기예상매출, 상반기매출, 하반기예상수주, 하반기수주, 하반기예상매출, 하반기매출, 장비비, 컨설팅비, 도구비, 착수, 종료, 고객담당자, 근무지, 업무, 도구, 과제성격, 사업지역, PM, 투입명단, 주간보고서, 실적보고, year],
            (err,result)=> {
              console.log(err);
            }
          )
        }
        else {
          db.query(
            "INSERT INTO project ( 팀수주,팀매출,프로젝트코드,프로젝트명,상태,실,고객사,고객부서,ManMonth,프로젝트계약금액_백만,상반기예상수주, 상반기수주, 상반기예상매출, 상반기매출, 하반기예상수주, 하반기수주, 하반기예상매출, 하반기매출, 장비비, 컨설팅비, 도구비, 착수, 종료, 고객담당자, 근무지, 업무, 도구, 과제성격, 사업지역, PM, 투입명단, 주간보고서, 실적보고, year, id) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?, ?)", //SQL 문 
            [팀수주,팀매출,프로젝트코드,프로젝트명,상태,실,고객사,고객부서,ManMonth,프로젝트계약금액_백만,상반기예상수주, 상반기수주, 상반기예상매출, 상반기매출, 하반기예상수주, 하반기수주, 하반기예상매출, 하반기매출, 장비비, 컨설팅비, 도구비, 착수, 종료, 고객담당자, 근무지, 업무, 도구, 과제성격, 사업지역, PM, 투입명단, 주간보고서, 실적보고, year, rows[0].id],
            (err,result)=> {
              console.log(err);
            }
          )
        }
      }
    );
  } catch (error) {
    res.sendStatus(401);
  }
});

// 1-4. 프로젝트 업데이트
app.post('/projects/update', (req, res) => {
  const 팀수주 = req.body.project.팀수주
  const 팀매출 = req.body.project.팀매출
  const 프로젝트코드 = req.body.project.프로젝트코드
  const 프로젝트명 = req.body.project.프로젝트명
  const 상태 = req.body.project.상태
  const 실 = req.body.project.실
  const 고객사 = req.body.project.고객사
  const 고객부서 = req.body.project.고객부서
  const ManMonth = req.body.project.ManMonth
  const 프로젝트계약금액_백만 = req.body.project.프로젝트계약금액_백만
  const 상반기예상수주 = req.body.project.상반기예상수주
  const 상반기수주 = req.body.project.상반기수주
  const 상반기예상매출 = req.body.project.상반기예상매출
  const 상반기매출 = req.body.project.상반기매출
  const 하반기예상수주 = req.body.project.하반기예상수주
  const 하반기수주 = req.body.project.하반기수주
  const 하반기예상매출 = req.body.project.하반기예상매출
  const 하반기매출 = req.body.project.하반기매출
  const 장비비 = req.body.project.장비비
  const 컨설팅비 = req.body.project.컨설팅비
  const 도구비 = req.body.project.도구비
  const 착수 = req.body.project.착수
  const 종료 = req.body.project.종료
  const 고객담당자 = req.body.project.고객담당자
  const 근무지 = req.body.project.근무지
  const 업무 = req.body.project.업무
  const 도구 = req.body.project.도구
  const 과제성격 = req.body.project.과제성격
  const 사업지역 = req.body.project.사업지역
  const PM = req.body.project.PM
  const 투입명단 = req.body.project.투입명단
  const id =  req.body.project.id
  const 주간보고서 = req.body.project.주간보고서
  const 실적보고 = req.body.project.실적보고
  const year = req.body.project.year
  const token = req.headers.authorization;
  try {
    const decoded = jwt.verify(token, secretObj.secret);
    db.query(
      "UPDATE project SET 팀수주=?,팀매출=?,프로젝트코드=?,프로젝트명=?,상태=?,실=?,고객사=?,고객부서=?,ManMonth=?,프로젝트계약금액_백만=?,상반기예상수주=?, 상반기수주=?, 상반기예상매출=?, 상반기매출=?, 하반기예상수주=?, 하반기수주=?, 하반기예상매출=?, 하반기매출=?, 장비비=?, 컨설팅비=?, 도구비=?, 착수=?, 종료=?, 고객담당자=?, 근무지=?, 업무=?, 도구=?, 과제성격=?, 사업지역=?, PM=?, 투입명단=?, 주간보고서=?, 실적보고=? WHERE year = ? and id = ?", //SQL 문 
      [팀수주,팀매출,프로젝트코드,프로젝트명,상태,실,고객사,고객부서,ManMonth,프로젝트계약금액_백만,상반기예상수주, 상반기수주, 상반기예상매출, 상반기매출, 하반기예상수주, 하반기수주, 하반기예상매출, 하반기매출, 장비비, 컨설팅비, 도구비, 착수, 종료, 고객담당자, 근무지, 업무, 도구, 과제성격, 사업지역, PM, 투입명단, 주간보고서, 실적보고, year, id],
      (err,result)=> {
        console.log(err);
      }
    );
  } catch (error) {
    res.sendStatus(401);
  }
})

// 1-5. 프로젝트 데이터 삭제
app.post('/projects/delete', (req, res) => {
  const id = req.body.id
  const year = req.body.year
  const token = req.headers.authorization;
  try {
    const decoded = jwt.verify(token, secretObj.secret);
    db.query(
        "DELETE FROM project WHERE id= ? and year = ?",
        [id, year],
        (err,result)=> {
          console.log(err);
        }
    );
  } catch (error) {
    res.sendStatus(401);
  }
})

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

// 2. 프로젝트 - WBS

// 2-1. WBS 구분

// 2-1-1. WBS 구분 데이터 로드
app.get("/wbs/resources", (req, res) => {
  const id = req.query.id;
  const year = req.query.year;
  const query = `SELECT * FROM wbs_resources WHERE projectId = '` + id + `' and year='` + year + `'`;
  const token = req.headers.authorization;
  try {
    const decoded = jwt.verify(token, secretObj.secret);
    db.query(query, (err, rows, fields) => {
      if (err) console.log(err);
      res.send(rows);
    });
  } catch (error) {
    res.sendStatus(401);
  }
});

// 2-1-2. WBS 구분 데이터 추가
app.post("/wbs/resources/add", (req, res) => {
  const name = req.body.name;
  const color = req.body.color;
  const year = req.body.year;
  const projectId = req.body.projectId;
  const token = req.headers.authorization;
  try {
    const decoded = jwt.verify(token, secretObj.secret);
    db.query(
      "INSERT INTO wbs_resources (name,color,year,projectId) VALUES (?,?,?,?)", //SQL 문
      [name, color, year, projectId],
      (err, result) => {
        if (err) console.log(err);
        res.send(result);
      }
    );
  } catch (error) {
    res.sendStatus(401);
  }
});

// 2-1-3. WBS 구분 데이터 수정
app.post("/wbs/resources/update", (req, res) => {
  const id = req.body.modalData.id;
  const name = req.body.modalData.name;
  const color = req.body.modalData.color;
  const token = req.headers.authorization;
  try {
    const decoded = jwt.verify(token, secretObj.secret);
    db.query(
      "UPDATE wbs_resources SET name = ?, color = ? WHERE id = ?", //SQL 문
      [name, color, id],
      (err, result) => {
        if (err) console.log(err);
        res.send(result);
      }
    );
  } catch (error) {
    res.sendStatus(401);
  }
});

// 2-1-4. WBS 구분 데이터 삭제
app.post("/wbs/resources/delete", (req, res) => {
  const id = req.body.id;
  const token = req.headers.authorization;
  try {
    const decoded = jwt.verify(token, secretObj.secret);
    db.query(
      `DELETE wr, ws, we FROM wbs_resources AS wr LEFT JOIN wbs_sub AS ws ON wr.id = ws.resourceId LEFT JOIN wbs_events AS we ON ws.id = we.subId WHERE wr.id = ?`, //SQL 문
      [id],
      (err, result) => {
        if (err) console.log(err);
        res.send(result);
      }
    );
  } catch (error) {
    res.sendStatus(401);
  }
});

// 2-2. 작업

// 2-2-1. WBS 작업 데이터 로드
app.get("/wbs/sub", (req, res) => {
  const id = req.query.id;
  const year = req.query.year;
  const query = `SELECT ws.* FROM wbs_sub as ws join wbs_resources as wr on wr.projectId  = '` + id + `' and wr.year ='` + year + `' and wr.id = ws.resourceId`;
  const token = req.headers.authorization;
  try {
    const decoded = jwt.verify(token, secretObj.secret);
    db.query(query, (err, rows, fields) => {
      if (err) console.log(err);
      res.send(rows);
    });
  } catch (error) {
    res.sendStatus(401);
  }
});

// 2-2-2. WBS 작업 데이터 추가
app.post("/wbs/sub/add", (req, res) => {
  const name = req.body.name;
  const 담당자 = req.body.담당자;
  const resourceId = req.body.resourceId;
  const token = req.headers.authorization;
  try {
    const decoded = jwt.verify(token, secretObj.secret);
    db.query(
      "INSERT INTO wbs_sub (name,담당자,resourceId) VALUES (?,?,?)", //SQL 문
      [name, 담당자, resourceId],
      (err, result) => {
        if (err) console.log(err);
        res.send(result);
      }
    );
  } catch (error) {
    res.sendStatus(401);
  }
});

// 2-2-3. WBS 작업 데이터 수정
app.post("/wbs/sub/update", (req, res) => {
  const id = req.body.modalData.id;
  const name = req.body.modalData.name;
  const 담당자 = req.body.modalData.담당자;
  const resourceId = req.body.modalData.resourceId;
  const token = req.headers.authorization;
  try {
    const decoded = jwt.verify(token, secretObj.secret);
    db.query(
      "UPDATE wbs_sub SET name = ?, 담당자 = ?, resourceId = ? WHERE id = ?", //SQL 문
      [name, 담당자, resourceId, id],
      (err, result) => {
        console.log(err);
        res.send(result);
      }
    );
  } catch (error) {
    res.sendStatus(401);
  }
});

// 2-2-4. WBS 작업 데이터 삭제
app.post("/wbs/sub/delete", (req, res) => {
  const id = req.body.id;
  const token = req.headers.authorization;
  try {
    const decoded = jwt.verify(token, secretObj.secret);
    db.query(
      `DELETE ws, we FROM wbs_sub AS ws LEFT JOIN wbs_events AS we ON ws.id = we.subId WHERE ws.id = ?`, //SQL 문
      [id],
      (err, result) => {
        if (err) console.log(err);
        res.send(result);
      }
    );
  } catch (error) {
    res.sendStatus(401);
  }
});

// 2-3. 일정

// 2-3-1. WBS 일정 데이터 로드
app.get("/wbs/events", (req, res) => {
  const id = req.query.id;
  const year = req.query.year;
  const query = `SELECT we.* FROM wbs_events as we join wbs_resources as wr on wr.projectId = '` + id + `' and wr.year = '` + year + `' join wbs_sub as ws on ws.resourceId = wr.id and ws.id = we.subId`;
  const token = req.headers.authorization;
  try {
    const decoded = jwt.verify(token, secretObj.secret);
    db.query(query, (err, rows, fields) => {
      if (err) console.log(err);
      res.send(rows);
    });
  } catch (error) {
    res.sendStatus(401);
  }
});

// 2-3-2. WBS 일정 데이터 추가
app.post("/wbs/events/add", (req, res) => {
  const start = req.body.start;
  const end = req.body.end;
  const text = req.body.text;
  const subId = req.body.subId;
  const resourceId = req.body.resourceId;
  const token = req.headers.authorization;
  try {
    const decoded = jwt.verify(token, secretObj.secret);
    db.query(
      "INSERT INTO wbs_events (start,end,text,subId,resourceId) VALUES (?,?,?,?,?)", //SQL 문
      [start, end, text, subId, resourceId],
      (err, result) => {
        if (err) console.log(err);
        res.send(result);
      }
    );
  } catch (error) {
    res.sendStatus(401);
  }
});

// 2-3-3. WBS 일정 데이터 수정
app.post("/wbs/events/update", (req, res) => {
  const start = req.body.modalData.start;
  const end = req.body.modalData.end;
  const text = req.body.modalData.text;
  const eventId = req.body.modalData.eventId;
  const subId = req.body.modalData.subId;
  const resourceId = req.body.modalData.resourceId;
  const token = req.headers.authorization;
  try {
    const decoded = jwt.verify(token, secretObj.secret);
    db.query(
      "UPDATE wbs_events SET start = ?, end = ?, text = ?, subId = ?, resourceId = ? WHERE id = ?", //SQL 문
      [start, end, text, subId, resourceId, eventId],
      (err, result) => {
        if (err) console.log(err);
        res.send(result);
      }
    );
  } catch (error) {
    res.sendStatus(401);
  }
});

// 2-3-4. WBS 일정 데이터 삭제
app.post("/wbs/events/delete", (req, res) => {
  const id = req.body.id;
  const token = req.headers.authorization;
  try {
    const decoded = jwt.verify(token, secretObj.secret);
    db.query(
      "DELETE FROM wbs_events WHERE id = ?", //SQL 문
      [id],
      (err, result) => {
        if (err) console.log(err);
        res.send(result);
      }
    );
  } catch (error) {
    res.sendStatus(401);
  }
});

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

// 3. 프로젝트 - 주간보고

// 3-1. 주간보고 가져오기
app.get('/reports',(req,res)=>{
  const token = req.headers.authorization;
  try {
    const decoded = jwt.verify(token, secretObj.secret);
    db.query(
      "SELECT * FROM report",
      (err,rows,fields)=>{
        res.send(rows);
      }
    );
  } catch (error) {
    res.sendStatus(401);
  }
});

// 3-2. 현재 주간보고 가져오기
app.get('/reports/search',(req,res)=>{
  const id = req.query.id
  const query = "SELECT * FROM report WHERE id = '"+id+"'"
  const token = req.headers.authorization;
  try {
    const decoded = jwt.verify(token, secretObj.secret);
    db.query(
      query,
      (err,rows,fields)=>{
        res.send(rows);
      }
    );
  } catch (error) {
    res.sendStatus(401);
  }
})

// 3-3. 지난 주간보고 가져오기
app.get('/reports/search/last',(req,res)=>{
  const project_id = req.query.pid
  const query = "SELECT * FROM report WHERE project_id = '"+project_id+"'"
  const token = req.headers.authorization;
  try {
    const decoded = jwt.verify(token, secretObj.secret);
    db.query(
      query,
      (err,rows,fields)=>{
        res.send(rows);
      }
    );
  } catch (error) {
    res.sendStatus(401);
  }
})

// 3-4. 주간보고서 등록
app.post("/reports/add", (req, res) =>{
  const project_id = req.body.report.project_id 
  const 작성자 = req.body.report.작성자 
  const 최종수정시간 = req.body.report.최종수정시간 
  const 금주계획 = req.body.report.금주계획 
  const 금주진행 = req.body.report.금주진행 
  const 차주계획 = req.body.report.차주계획 
  const 특이사항 = req.body.report.특이사항 
  const 비고 = req.body.report.비고 
  const token = req.headers.authorization;
  try {
    const decoded = jwt.verify(token, secretObj.secret);
    db.query(
      "INSERT INTO report (project_id, 작성자, 최종수정시간, 금주계획, 금주진행, 차주계획, 특이사항, 비고) VALUES (?,?,?,?,?,?,?,?)", //SQL 문
      [project_id, 작성자, 최종수정시간, 금주계획, 금주진행, 차주계획, 특이사항, 비고],
      (err,result)=> {
      }
   );
  } catch (error) {
    res.sendStatus(401);
  }
});

// 3-5. 주간보고서 수정
app.post('/reports/update', (req, res) => {
  const 작성자 = req.body.report.작성자 
  const 최종수정시간 = req.body.최종수정시간 
  const 금주계획 = req.body.report.금주계획 
  const 금주진행 = req.body.report.금주진행 
  const 차주계획 = req.body.report.차주계획
  const 특이사항 = req.body.report.특이사항 
  const 비고 = req.body.report.비고 
  const id = req.body.id
  const token = req.headers.authorization;
  try {
    const decoded = jwt.verify(token, secretObj.secret);
    db.query(
      "UPDATE report SET 작성자 = ? , 최종수정시간 = ? , 금주계획 = ? , 금주진행 = ? , 차주계획 = ? , 특이사항 = ? , 비고 = ? WHERE id = ?", //SQL 문 
      [작성자, 최종수정시간, 금주계획, 금주진행, 차주계획, 특이사항, 비고, id],
      (err,result)=> {
      }
    );
  } catch (error) {
    res.sendStatus(401);
  }
})

// 3-6. 주간보고서 삭제
app.post('/reports/delete', (req, res) => {
  const id = req.body.id
  const token = req.headers.authorization;
  try {
    const decoded = jwt.verify(token, secretObj.secret);
    db.query(
      "DELETE FROM report WHERE id = ?", //SQL 문 
      [id],
      (err,result)=> {
        console.log(err);
      }
    );
  } catch (error) {
    res.sendStatus(401);
  }
})

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

// 4. 프로젝트 - 회의록

// 4-1. 회의록 DB 불러오기
app.get('/meetings',(req,res)=>{
  const token = req.headers.authorization;
  try {
    const decoded = jwt.verify(token, secretObj.secret);
    db.query(
      "SELECT * FROM meeting",
      (err,rows,fields)=>{
        res.send(rows);
      }
    );
  } catch (error) {
    res.sendStatus(401);
  }
})

// 4-2. 회의록 디테일 불러오기
app.get('/meetings/search',(req,res)=>{
  const id = req.query.id
  const query = "SELECT * FROM meeting WHERE id = '"+id+"'"
  const token = req.headers.authorization;
  try {
    const decoded = jwt.verify(token, secretObj.secret);
    db.query(
        query,
        (err,rows,fields)=>{
          res.send(rows);
        }
    );
  } catch (error) {
    res.sendStatus(401);
  }
})

// 4-3. 회의록 수정
app.post('/meetings/update', (req, res) => {
  const 회의명 = req.body.meetings.회의명
  const 회의장소= req.body.meetings.회의장소
  const 회의일시 = req.body.meetings.회의일시
  const 작성일시 = req.body.meetings.작성일시
  const 작성자 = req.body.meetings.작성자
  const 참석자 = req.body.meetings.참석자
  const 고객사 = req.body.meetings.고객사
  const 회의내용 = req.body.meetings.회의내용
  const 이슈사항 = req.body.meetings.이슈사항
  const id =  req.body.meetings.id
  const token = req.headers.authorization;
  try {
    const decoded = jwt.verify(token, secretObj.secret);
    db.query(
        "UPDATE meeting SET 회의명=?,회의장소=?,회의일시=?,작성일시=?,작성자=?,참석자=?,고객사=?,회의내용=?,이슈사항=? WHERE id = ?", //SQL 문 
        [회의명,회의장소,회의일시,작성일시,작성자,참석자,고객사,회의내용,이슈사항,id],
        (err,result)=> {
          console.log(err);
        }
    );
  } catch (error) {
    res.sendStatus(401);
  }
})

// 4-4. 회의록 추가
app.post("/meetings/add", (req, res) =>{
  const 회의명 = req.body.meetings.회의명
  const 회의장소= req.body.meetings.회의장소
  const 회의일시 = req.body.meetings.회의일시
  const 작성일시 = req.body.meetings.작성일시
  const 작성자 = req.body.meetings.작성자
  const 참석자 = req.body.meetings.참석자
  const 고객사 = req.body.meetings.고객사
  const 회의내용 = req.body.meetings.회의내용
  const 이슈사항 = req.body.meetings.이슈사항
  const token = req.headers.authorization;
  try {
    const decoded = jwt.verify(token, secretObj.secret);
    db.query(
      "INSERT INTO meeting ( 회의명,회의장소,회의일시,작성일시,작성자,참석자,고객사,회의내용,이슈사항) VALUES (?,?,?,?,?,?,?,?,?)", //SQL 문 
      [회의명,회의장소,회의일시,작성일시,작성자,참석자,고객사,회의내용,이슈사항],
      (err,result)=> {
        console.log(err);
      }
    );
  } catch (error) {
    res.sendStatus(401);
  }
});

// 4-5. 회의록 삭제
app.post('/meetings/delete', (req, res) => {
  const id = req.body.id
  const token = req.headers.authorization;
  try {
    const decoded = jwt.verify(token, secretObj.secret);
    db.query(
        "DELETE FROM meeting WHERE id= ?",
        [id],
        (err,result)=> {
          console.log(err);
        }
    );
  } catch (error) {
    res.sendStatus(401);
  }
})

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

// 교육관리

// 0. 교육관리 엑셀 Export
app.get('/education/excel', (req, res) => {
  const query = `SELECT team, stu_name, edu_name, learn_time, DATE_FORMAT(start_date, "%Y-%m-%d") AS start_date, DATE_FORMAT(end_date, "%Y-%m-%d") AS end_date, cost FROM education ORDER BY team`;
  const token = req.headers.authorization;
  try {
    const decoded = jwt.verify(token, secretObj.secret);
    db.query(
      query,
      (err, rows, fields) => {
          if(err) {console.log(err)};
          res.send(rows);
      }
  );
  } catch (error) {
    res.sendStatus(401);
  }
})

// 1. 교육관리 팀 별 리스트

// 1-1. 교육관리 팀 별 팀 멤버 데이터 로드
app.get('/education/team_member', (req, res) => {
  const team = req.query.team;
  const query = `SELECT id, name, 직급 FROM member where team = ` + team;
  const token = req.headers.authorization;
  try {
    const decoded = jwt.verify(token, secretObj.secret);
    db.query(
      query,
      (err, rows, fields) => {
          if(err) {console.log(err)};
          res.send(rows);
      }
  );
  } catch (error) {
    res.sendStatus(401);
  }
})

// 1-2. 교육관리 팀 별 데이터 로드
app.get("/education/read", (req, res) => {
  const team = req.query.team;
  const year = req.query.year;
  const query =
    "SELECT num, stu_name, edu_name, learn_time, date_format(start_date, '%Y-%m-%d') AS start_date, date_format(end_date, '%Y-%m-%d') AS end_date, cost FROM education WHERE team=" 
    + team + " and YEAR(start_date)=" + year + 
    " ORDER BY stu_name ASC, start_date ASC";
  const token = req.headers.authorization;
  try {
    const decoded = jwt.verify(token, secretObj.secret);
    db.query(
      query, (err, rows, fields) => {
        if (err) console.log(err);
        res.send(rows);
      }
    );
  } catch (error) {
    res.sendStatus(401);
  }
});

// 1-3. 교육관리 팀 별 데이터 추가
app.post("/education/add", (req, res) => {
  const team = req.body.team;
  const stu_name = req.body.stu_name;
  const edu_name = req.body.edu_name;
  const learn_time = req.body.learn_time;
  const start_date = req.body.start_date;
  const end_date = req.body.end_date;
  const cost = req.body.cost;

  const query = "INSERT INTO education (stu_name,edu_name,learn_time,start_date,end_date,cost,team) VALUES (?,?,?,?,?,?,?)"
  const token = req.headers.authorization;
  try {
    const decoded = jwt.verify(token, secretObj.secret);
    db.query(
      query,
      [stu_name, edu_name, learn_time, start_date, end_date, cost, team],
      (err, result) => {
        if (err) console.log(err);
        res.send(result);
      }
    );
  } catch (error) {
    res.sendStatus(401);
  }
});

// 1-4. 교육관리 팀 별 데이터 수정
app.post("/education/update", (req, res) => {
  const token = req.headers.authorization;
  const num = req.body.num;
  const stu_name = req.body.stu_name;
  const edu_name = req.body.edu_name;
  const learn_time = req.body.learn_time;
  const start_date = req.body.start_date;
  const end_date = req.body.end_date;
  const cost = req.body.cost;

  const query = "UPDATE education SET stu_name = ? , edu_name = ?, learn_time = ?, start_date = ?, end_date= ? , cost =? WHERE num = ?"

  try {
    const decoded = jwt.verify(token, secretObj.secret);
    db.query(
      query,
      [stu_name, edu_name, learn_time, start_date, end_date, cost, num],
      (err, result) => {
        console.log(err);
      }
    );
  } catch (error) {
    res.sendStatus(401);
  }
});

// 1-5. 교육관리 팀 별 데이터 삭제
app.post("/education/delete", (req, res) => {
  const num = req.body.num;
  const query = "DELETE FROM education WHERE num= ?"
  const token = req.headers.authorization;
  try {
    const decoded = jwt.verify(token, secretObj.secret);
    db.query(
      query, //SQL 문
      [num],
      (err, result) => {
        console.log(err);
      }
    );
  } catch (error) {
    res.sendStatus(401);
  }
});

// 2. 교육관리 그래프

// 2-1. 교육관리 그래프를 위한 목표시간 데이터 로드
app.get("/education/goal", (req, res) => {
  const query = `SELECT YEAR(start_date) AS year, goal FROM education group by year`;
  const token = req.headers.authorization;
  try {
    const decoded = jwt.verify(token, secretObj.secret);
    db.query(query, (err, rows, fields) => {
      if (err) console.log(err);
      res.send(rows);
    });
  } catch (error) {
    res.sendStatus(401);
  }
});

// 2-2. 교육관리 그래프를 위한 목표시간 데이터 수정
app.post("/education/goal/update", (req, res) => {
  const goal = req.body.goal;
  const year = req.body.year;
  const query = `UPDATE education SET goal=? WHERE YEAR(start_date)=?`;
  const token = req.headers.authorization;
  try {
    const decoded = jwt.verify(token, secretObj.secret);
    db.query(query, [goal, year], (err, rows, fields) => {
      if (err) console.log(err);
      res.send(rows);
    });
  } catch (error) {
    res.sendStatus(401);
  }
});

// 2-4. 교육관리 그래프의 계산을 위해 팀 별 인원수 로드
app.get('/education/teams/count', (req, res) => {
  const team = req.query.team;
  const query = `SELECT COUNT(*) AS count from member where team=` + team + ` and 직급 != '인턴'`;
  const token = req.headers.authorization;
  try {
    const decoded = jwt.verify(token, secretObj.secret);
    db.query(
      query,
      (err, rows, fields) => {
          if(err) {console.log(err)};
          res.send(rows);
      }
  );
  } catch (error) {
    res.sendStatus(401);
  }
})

// 2-5. 교육관리 그래프를 위해 년도별 팀 당 상/하반기 이수시간, 연간 금액 합 데이터 로드
app.get('/education/teams/data', (req, res) => {
  const team = req.query.team;
  const year = req.query.year;
  const query = `SELECT SUM(IF(MONTH(start_date) < 7, learn_time, 0)) AS fh_learn_time_sum, SUM(IF(MONTH(start_date) >= 7, learn_time, 0)) AS sh_learn_time_sum, SUM(cost) AS cost_sum FROM education WHERE team=` + team + ` and YEAR(start_date)=` + year;
  const token = req.headers.authorization;
  try {
    const decoded = jwt.verify(token, secretObj.secret);
    db.query(
      query,
      (err, rows, fields) => {
          if(err) {console.log(err)};
          res.send(rows);
      }
  );
  } catch (error) {
    res.sendStatus(401);
  }
})

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

// 자산관리

// 1. 자산관리 데이터 로드
app.get('/equips', (req,res) => {
  const token = req.headers.authorization;
  try {
    const decoded = jwt.verify(token, secretObj.secret);
    db.query('SELECT * FROM equipment', (err,rows,fields)=> {
      res.send(rows);
    });
  } catch (error) {
    res.sendStatus(401);
  }
})

// 2. 자산관리 데이터 추가
app.post("/equips/add", (req, res) => {
  const num = req.body.num;
  const ename = req.body.ename;
  const sort = req.body.sort;
  const version = req.body.version;
  const serial = req.body.serial;
  const buyyear = req.body.buyyear;
  const buycost = req.body.buycost;
  const supervise = req.body.supervise;
  const register = req.body.register;
  const user = req.body.user;
  const token = req.headers.authorization;
  try {
    const decoded = jwt.verify(token, secretObj.secret);
    db.query(
      "INSERT INTO equipment (num,ename,sort,version,serial,buyyear,buycost,supervise,register,user) VALUES (?,?,?,?,?,?,?,?,?,?)", //SQL 문
      [num, ename, sort, version, serial, buyyear, buycost, supervise, register, user],
      (err, result) => {
        if (err) console.log(err);
      }
    );
  } catch (error) {
    res.sendStatus(401);
  }
});

// 3. 자산관리 데이터 수정
app.post("/equips/update", (req, res) => {
  const num = req.body.num;
  const ename = req.body.ename;
  const sort = req.body.sort;
  const version = req.body.version;
  const serial = req.body.serial;
  const buyyear = req.body.buyyear;
  const buycost = req.body.buycost;
  const supervise = req.body.supervise;
  const register = req.body.register;
  const user = req.body.user;
  const token = req.headers.authorization;
  try {
    const decoded = jwt.verify(token, secretObj.secret);
    db.query(
      "UPDATE equipment SET  ename = ?, sort = ? , version = ? , serial = ? , buyyear = ?, buycost = ? , supervise = ?, register = ? , user = ? WHERE num = ?", //SQL 문
      [ename, sort, version, serial, buyyear, buycost, supervise, register, user, num],
      (err, result) => {
        if (err) console.log(err);
      }
    );
  } catch (error) {
    res.sendStatus(401);
  }
});

// 4. 자산관리 데이터 삭제
app.post("/equips/delete", (req, res) => {
  const num = req.body.num;
  const token = req.headers.authorization;
  try {
    const decoded = jwt.verify(token, secretObj.secret);
    db.query(
      "DELETE FROM equipment WHERE num= ?", //SQL 문
      [num],
      (err, result) => {
        if (err) console.log(err);
      }
    );
  } catch (error) {
    res.sendStatus(401);
  }
});

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

// 프로젝트룸 예약

// 1. 예약 데이터 로드
app.get('/reservations', (req,res) => {
  const token = req.headers.authorization;
  try {
    const decoded = jwt.verify(token, secretObj.secret);
    db.query('SELECT * FROM reservation', (err,rows,fields)=> {
      res.send(rows);
    });
  } catch (error) {
    res.sendStatus(401);
  }
})

// 2. 예약 데이터 추가
app.post("/reservations/add", (req, res) => {
  const title = req.body.modalData.title;
  const start = req.body.modalData.start;
  const end = req.body.modalData.end;
  const 예약자 = req.body.modalData.예약자;
  const 예약내용 = req.body.modalData.예약내용;
  const token = req.headers.authorization;
  try {
    const decoded = jwt.verify(token, secretObj.secret);
    db.query(
      "INSERT INTO reservation (title,start,end,예약자,예약내용) VALUES (?,?,?,?,?)", //SQL 문
      [title, start, end, 예약자, 예약내용],
      (err, result) => {
        if (err) console.log(err);
      }
    );
  } catch (error) {
    res.sendStatus(401);
  }
});

// 3. 예약 데이터 삭제
app.post("/reservations/delete", (req, res) => {
  const id = req.body.id;
  const token = req.headers.authorization;
  try {
    const decoded = jwt.verify(token, secretObj.secret);
    db.query(
      "DELETE FROM reservation WHERE id= ?", //SQL 문
      [id],
      (err, result) => {
        if (err) console.log(err);
      }
    );
  } catch (error) {
    res.sendStatus(401);
  }
});

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

// 관리자 스케줄

// 1. 스케줄 불러오기
app.get('/schedule',(req,res)=>{
  const token = req.headers.authorization;
  try {
    const decoded = jwt.verify(token, secretObj.secret);
    db.query(
      "SELECT * FROM manager_schedule",
      (err,rows,fields)=>{
        res.send(rows);
        console.log(err);
      }
    );
  } catch (error) {
    res.sendStatus(401);
  }
})

// 2. 선택된 스케줄
app.get('/schedule/search',(req,res)=>{
  const id = req.query.id
  const query = "SELECT * FROM manager_schedule WHERE id = '"+id+"'"
  const token = req.headers.authorization;
  try {
    const decoded = jwt.verify(token, secretObj.secret);
    db.query(
      query,
      (err,rows,fields)=>{
        res.send(rows);
        console.log(err);
      }
    );
  } catch (error) {
    res.sendStatus(401);
  }
})

// 3. 스케줄 추가
app.post("/schedule/add", (req, res) =>{
  const schedule = req.body.schedule
  const token = req.headers.authorization;
  schedule.forEach(element => {
      const 이름 = element.이름
      const 날짜 = element.날짜
      const 오전 = element.오전
      const 오후 = element.오후
      try {
        const decoded = jwt.verify(token, secretObj.secret);
        db.query(
          "SELECT * FROM manager_schedule WHERE 이름 = ? AND 날짜 = ?",
          [이름, 날짜],
          (err,rows,fields)=>{
          if(rows.length == 0){
            db.query(
              "INSERT INTO manager_schedule (이름, 날짜, 오전, 오후) VALUES (?,?,?,?)", //SQL 문 
              [이름, 날짜, 오전, 오후],
              (err,result)=> {
                console.log(err);
              }
            );
          }
          else{
            db.query(
              "UPDATE manager_schedule SET 오전 = ?, 오후 = ? WHERE 이름 = ? AND 날짜 = ?",
              [오전, 오후, 이름, 날짜],
              (err,result)=> {
                console.log(err);
              });
            }
          }
        );
      } catch (error) {
        res.sendStatus(401);
      }
    });
  });

// 4. 스케줄 수정
app.post('/schedule/update', (req, res) => {
  const 오전 = req.body.오전
  const 오후 = req.body.오후
  const id = req.body.id
  const token = req.headers.authorization;
  try {
    const decoded = jwt.verify(token, secretObj.secret);
    db.query(
        "UPDATE manager_schedule SET 오전=?, 오후=? WHERE id = ?", //SQL 문
        [오전, 오후, id],
        (err,result)=> {
        }
    );
  } catch (error) {
    res.sendStatus(401);
  }
})

// 5. 스케줄 삭제
app.post('/schedule/delete', (req, res) => {
  const id = req.body.id
  const token = req.headers.authorization;
  try {
    const decoded = jwt.verify(token, secretObj.secret);
    db.query(
        "DELETE FROM manager_schedule WHERE id = ?", //SQL 문
        [id],
        (err,result)=> {
          console.log(err);
        }
    );
  } catch (error) {
    res.sendStatus(401);
  }
})

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

//조직도

// 조직도에서 엑셀파일을 서버쪽으로 upload하는 기능

// app.post("/api/upload", (req, res, next) => {
//   // FormData의 경우 req로 부터 데이터를 얻을수 없다.
//   // upload 핸들러(multer)를 통해서 데이터를 읽을 수 있다
  
//   upload(req, res, function(err) {
//     if (err instanceof multer.MulterError) {
//       return next(err);
//     } else if (err) {
//       return next(err);
//     }
//     console.log('원본파일명 : ' + req.file.originalname)
//     console.log('저장파일명 : ' + req.file.filename)
//     console.log('크기 : ' + req.file.size)
//     // console.log('경로 : ' + req.file.location) s3 업로드시 업로드 url을 가져옴
//     return res.json({success:1});
//   });
// });

// // 서버의 uploads 폴더에서 가장 최근에 저장된 파일 찾는 기능 

// const getMostRecentFile = (dir) => {
//   const files = orderReccentFiles(dir);
//   return files.length ? files[0].file : undefined;
// };

// const orderReccentFiles = (dir) => {
//   return fs.readdirSync(dir)
//     .filter((file) => fs.lstatSync(path.join(dir, file)).isFile())
//     .map((file) => ({ file, mtime: fs.lstatSync(path.join(dir, file)).mtime }))
//     .sort((a, b) => b.mtime.getTime() - a.mtime.getTime());
// };

// const fileName = getMostRecentFile(path.join(__dirname, "./uploads"));
// csvtojson().fromFile(path.join(__dirname, "./uploads", fileName)).then(source => {
  
//   // Fetching the data from each row and inserting to the table "products"
//   for (var i = 0; i < source.length; i++) {
//     var Groupt = source[i]["그룹"],
//       Namet = source[i]["이름"],
//       Emailt = source[i]["이메일"],
//       Phonet = source[i]["휴대전화"]
//       Addresst = source[i]["집주소"]
//       직급t = source[i]["직위"]
//       Agencyt = source[i]["부서명"]
//       Memot = source[i]["메모"]
//       Datet = source[i]["입사일"]
//       HPT = source[i]["홈페이지"]
//       ST = source[i]["사원번호"]
//       NT = source[i]["내선번호"]
//     var insertStatement = "INSERT INTO posts values(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";
//     var items = [Groupt, Namet, Emailt, Phonet, Addresst, 직급t, Agencyt, Memot, Datet, HPT, ST, NT];

//     db.query("SELECT * FROM posts WHERE 이메일=?", [Emailt], (err, result) => {
//       if (err) console.log(err);
//       if (result.length == 0) {
//         db.query(insertStatement, items, (err, result) => {
//           if (err) console.log(err);
//         });
//       }
//     });
//     // Inserting data of current row into database
//   }
//   console.log("Records inserted into database successfully...!!");
// });

// app.post("/posts/delete", (req, res) => {
//   const 이메일 = req.body.이메일;
//   db.query(
//     "DELETE FROM posts WHERE 이메일= ?", //SQL 문
//     [이메일],
//     (err, result) => {
//       if (err) console.log(err);
//     }
//   );
// });
