// 프로필 이미지 변경 함수
function updateProfileImage(event) {
    const file = event.target.files[0];
    const reader = new FileReader();

    reader.onload = function(e) {
        // 파일이 로드된 후, 이미지 src를 변경
        document.getElementById('profile-img').src = e.target.result;
    }

    // 파일 읽기
    if (file) {
        reader.readAsDataURL(file);
    }
}

// 로그아웃 함수
function logout() {
    axios.get("/oauth2/logout", {}, { withCredentials: true })
        .then(res => {
            if (res.data) {
                // 로그아웃 성공 후 리디렉션
                document.location.href = "/signIn";
            }
        })
        .catch(err => {
            console.log(err);
        });
}