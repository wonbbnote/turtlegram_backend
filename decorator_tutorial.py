def wrapper_function(func):
    def decorated_function():  # 형태 잘 기억 -> wrapper 안 decorated 함수 넣기
        print("함수 이전에 실행")
        func()  # 인자값으로 받은 함수 실행
        print("함수 이후에 실행")
    return decorated_function  # wrapper function반환으로 데코레이트 함수 반환


@wrapper_function  # new_function = wrapper_function(basic_function)과 동일
def basic_function():
    print("실행하고자 하는 함수")

# 1. 그냥 basic_function()  # -> 실행하고자 하는 함수


# 2. wrapper_function에 basic_function 넣어주기
new_function = wrapper_function(basic_function)
new_function()
'''
함수 이전에 실행
실행하고자 하는 함수 
함수 이후에 실행
*회원 로그인 jwt 토큰은 모든 api에서 공통적으로 사용하기 때문에 데코레이터 함수 사용하기 좋은 경우
'''

# 3.basic_function에 @wrapper_function붙이면 그냥 basic_function불러도
# 2번처럼 값이 도출
# basic_function()


# Q. @wrapper_function을 붙인 이후
# new_function = wrapper_function(basic_function)
# new_function() 를 실행시키면
'''함수 이전에 실행
함수 이전에 실행
실행하고자 하는 함수
함수 이후에 실행
함수 이후에 실행??'''
