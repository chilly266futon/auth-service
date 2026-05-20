package grpc

import (
	"context"

	"github.com/chilly266futon/auth-service/internal/dto/auth"
	"github.com/chilly266futon/auth-service/internal/service"
	pb "github.com/chilly266futon/exchange-service-contracts/gen/pb/auth"
)

type AuthServer struct {
	pb.UnimplementedAuthServiceServer
	useCase service.AuthService
}

func NewAuthServer(useCase service.AuthService) *AuthServer {
	return &AuthServer{useCase: useCase}
}

func (s *AuthServer) Register(ctx context.Context, pbReq *pb.RegisterRequest) (*pb.RegisterResponse, error) {
	req := auth.RegisterRequest{
		Email:    pbReq.Email,
		Password: pbReq.Password,
		Username: pbReq.Username,
	}

	resp, err := s.useCase.Register(ctx, req)
	if err != nil {
		return nil, err
	}

	return &pb.RegisterResponse{UserId: resp.UserID}, nil
}

func (s *AuthServer) Login(ctx context.Context, pbReq *pb.LoginRequest) (*pb.LoginResponse, error) {
	req := auth.LoginRequest{
		Email:    pbReq.Email,
		Password: pbReq.Password,
	}

	resp, err := s.useCase.Login(ctx, req)
	if err != nil {
		return nil, err
	}

	return &pb.LoginResponse{
		AccessToken:  resp.AccessToken,
		RefreshToken: resp.RefreshToken,
		UserId:       resp.UserID,
		Roles:        resp.Roles,
	}, nil
}

func (s *AuthServer) RefreshToken(ctx context.Context, pbReq *pb.RefreshTokenRequest) (*pb.RefreshTokenResponse, error) {
	req := auth.RefreshTokenRequest{
		RefreshToken: pbReq.RefreshToken,
	}

	resp, err := s.useCase.RefreshToken(ctx, req)
	if err != nil {
		return nil, err
	}

	return &pb.RefreshTokenResponse{
		AccessToken:  resp.AccessToken,
		RefreshToken: resp.RefreshToken,
		UserId:       resp.UserID,
		Roles:        resp.Roles,
	}, nil
}

func (s *AuthServer) ValidateToken(ctx context.Context, pbReq *pb.ValidateTokenRequest) (*pb.ValidateTokenResponse, error) {
	req := auth.ValidateTokenRequest{
		Token: pbReq.Token,
	}

	resp, err := s.useCase.ValidateToken(req)
	if err != nil {
		return nil, err
	}

	return &pb.ValidateTokenResponse{
		UserId: resp.UserID,
		Roles:  resp.Roles,
		Valid:  resp.Valid,
	}, nil
}
