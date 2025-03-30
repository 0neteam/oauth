
// 로그아웃 함수
function logout() {
    axios.get("/oauth2/logout", {}, { withCredentials: true })
        .then(res => {

			console.log(res);
            if (res.data) {
                // 로그아웃 성공 후 리디렉션
                document.location.href = "/oauth2/logout";

            }
        })
        .catch(err => {
            console.log(err);
        });
}

function switchTab(tabId) {
    document.querySelectorAll('.tab-content').forEach(tab => tab.classList.remove('active'));
    document.querySelectorAll('.tab').forEach(tab => tab.classList.remove('active'));
    document.getElementById(tabId).classList.add('active');
    document.querySelector(`.tab[onclick="switchTab('${tabId}')"]`).classList.add('active');
}