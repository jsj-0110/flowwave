```javascript
// ================================
// 모바일 메뉴
// ================================

const menuButton =
  document.querySelector('.menu-button');

const mobileMenu =
  document.querySelector('.mobile-menu');


if (menuButton && mobileMenu) {

  menuButton.addEventListener('click', () => {

    mobileMenu.classList.toggle('open');

  });


  document
    .querySelectorAll('.mobile-menu a')
    .forEach(link => {

      link.addEventListener('click', () => {

        mobileMenu.classList.remove('open');

      });

    });

}



// ================================
// MUT BELT RANKING
// ================================


// 관리자 페이지에서 저장한 선수 데이터 가져오기

function getPlayers() {

  const saved =
    localStorage.getItem("MUT_PLAYERS");


  if (!saved) {

    return [];

  }


  return JSON.parse(saved);

}



// ================================
// 점수 계산
// 금 5점 / 은 3점 / 동 1점
// ================================

function calculatePoints(player) {

  return (

    Number(player.gold || 0) * 5 +

    Number(player.silver || 0) * 3 +

    Number(player.bronze || 0)

  );

}



// ================================
// 랭킹 표시
// ================================

function showRanking(belt) {


  const rankingList =
    document.getElementById(
      "rankingList"
    );


  const rankingTitle =
    document.getElementById(
      "rankingBeltTitle"
    );


  if (
    !rankingList ||
    !rankingTitle
  ) {

    return;

  }



  rankingTitle.textContent =
    belt + " BELT";



  let players =
    getPlayers();



  // 선택한 벨트만 표시

  players =
    players.filter(function(player) {

      return player.belt === belt;

    });



  // 점수 계산

  players.forEach(function(player) {

    player.points =
      calculatePoints(player);

  });



  // 점수순 정렬

  players.sort(function(a, b) {

    return b.points - a.points;

  });



  rankingList.innerHTML =
    "";



  // 선수 없음

  if (
    players.length === 0
  ) {

    rankingList.innerHTML = `

      <tr>

        <td colspan="7">

          아직 등록된 선수가 없습니다.

        </td>

      </tr>

    `;

    return;

  }



  // 선수 표시

  players.forEach(function(
    player,
    index
  ) {


    const row =
      document.createElement("tr");



    row.innerHTML = `

      <td>
        ${index + 1}
      </td>

      <td>
        ${player.name}
      </td>

      <td>
        ${player.gym}
      </td>

      <td>
        ${player.gold}
      </td>

      <td>
        ${player.silver}
      </td>

      <td>
        ${player.bronze}
      </td>

      <td>
        ${player.points}점
      </td>

    `;



    rankingList.appendChild(
      row
    );

  });

}



// ================================
// 벨트 버튼 클릭
// ================================

const beltButtons =
  document.querySelectorAll(
    ".belt-ranking-btn"
  );


beltButtons.forEach(function(button) {


  button.addEventListener(
    "click",
    function() {


      beltButtons.forEach(
        function(btn) {

          btn.classList.remove(
            "active"
          );

        }
      );



      button.classList.add(
        "active"
      );



      const selectedBelt =
        button.getAttribute(
          "data-belt"
        );



      showRanking(
        selectedBelt
      );

    }
  );

});



// ================================
// 처음에는 WHITE BELT 표시
// ================================

showRanking("WHITE");



// ======================================================
// MUT 대회 일정
// ======================================================


// 저장된 대회 가져오기

function getEvents() {

  const saved =
    localStorage.getItem(
      "MUT_EVENTS"
    );


  if (!saved) {

    return [];

  }


  return JSON.parse(saved);

}



// ================================
// 홈페이지 대회 일정 표시
// ================================

function loadEventsToHomepage() {


  const eventList =
    document.getElementById(
      "homepageEventList"
    );


  // 홈페이지에 대회 목록 영역이 없으면 종료

  if (!eventList) {

    return;

  }



  const events =
    getEvents();



  eventList.innerHTML =
    "";



  // 등록된 대회가 없는 경우

  if (
    events.length === 0
  ) {

    eventList.innerHTML = `

      <div class="homepage-event-empty">

        아직 등록된 대회가 없습니다.

      </div>

    `;

    return;

  }



  // 대회 표시

  events.forEach(function(event) {


    // 예전 데이터 호환

    if (
      typeof event.registrationOpen ===
      "undefined"
    ) {

      event.registrationOpen =
        true;

    }



    const card =
      document.createElement(
        "article"
      );


    card.className =
      "homepage-event-card";



    card.innerHTML = `

      <div class="homepage-event-poster">

        <img
          src="${event.poster}"
          alt="${event.name}"
        >

      </div>


      <div class="homepage-event-info">


        <div class="homepage-event-status">

          ${
            event.registrationOpen
              ? "🟢 참가 신청 진행 중"
              : "🔴 참가 신청 마감"
          }

        </div>


        <h3>

          ${event.name}

        </h3>


        <div class="homepage-event-details">


          <p>

            <span>DATE</span>

            <strong>
              ${event.date}
            </strong>

          </p>


          <p>

            <span>PLACE</span>

            <strong>
              ${event.place}
            </strong>

          </p>


          <p>

            <span>TIME</span>

            <strong>
              ${event.time}
            </strong>

          </p>


        </div>


        ${
          event.description
            ? `
              <p class="homepage-event-description">

                ${event.description}

              </p>
            `
            : ""
        }


        ${
          event.registrationOpen

            ? `

              <a
                href="registration.html?eventId=${event.id}"
                class="homepage-registration-button"
              >

                참가 신청

                <span>→</span>

              </a>

            `

            : `

              <div
                class="homepage-registration-closed"
              >

                참가 신청 마감

              </div>

            `
        }


      </div>

    `;



    eventList.appendChild(
      card
    );

  });

}



// ================================
// 대회 일정 실행
// ================================

loadEventsToHomepage();



// ================================
// 다른 탭에서 데이터가 변경됐을 때
// 홈페이지 자동 새로고침
// ================================

window.addEventListener(
  "storage",
  function(event) {


    if (
      event.key === "MUT_EVENTS"
    ) {

      loadEventsToHomepage();

    }


    if (
      event.key === "MUT_PLAYERS"
    ) {

      const activeButton =
        document.querySelector(
          ".belt-ranking-btn.active"
        );


      if (activeButton) {

        showRanking(
          activeButton.getAttribute(
            "data-belt"
          )
        );

      }

    }

  }
);
```
