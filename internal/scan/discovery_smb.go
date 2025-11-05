package scan

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/oiweiwei/go-msrpc/dcerpc"
	"github.com/oiweiwei/go-msrpc/msrpc/dtyp"
	srvsvc "github.com/oiweiwei/go-msrpc/msrpc/srvs/srvsvc/v3"
	wkssvc "github.com/oiweiwei/go-msrpc/msrpc/wkst/wkssvc/v1"
	"github.com/oiweiwei/go-msrpc/ssp"
	"github.com/oiweiwei/go-msrpc/ssp/credential"
	"github.com/oiweiwei/go-msrpc/ssp/gssapi"
)

const (
	smbPipeWKSSVC = "wkssvc"
	smbPipeSRVSVC = "srvsvc"
)

func lookupSMBInfo(ctx context.Context, host string) *SMBInfo {
	if ctx == nil || ctx.Err() != nil {
		return nil
	}

	if info, err := querySMBEndpoint(ctx, host, smbPipeWKSSVC, "wkssvc", fetchWKSSVCInfo); err == nil && info != nil {
		return info
	}

	if info, err := querySMBEndpoint(ctx, host, smbPipeSRVSVC, "srvsvc", fetchSRVSVCInfo); err == nil && info != nil {
		return info
	}

	return nil
}

type smbQueryFunc func(context.Context, dcerpc.Conn) (SMBInfo, error)

func querySMBEndpoint(parentCtx context.Context, host, pipe, source string, fn smbQueryFunc) (*SMBInfo, error) {
	if parentCtx.Err() != nil {
		return nil, parentCtx.Err()
	}

	callCtx, cancel := context.WithTimeout(parentCtx, 4*time.Second)
	secCtx := gssapi.NewSecurityContext(callCtx,
		gssapi.WithCredential(credential.Anonymous()),
		gssapi.WithMechanismFactory(ssp.NTLM),
		gssapi.WithMechanismFactory(ssp.SPNEGO),
	)

	conn, err := dcerpc.Dial(secCtx, host,
		dcerpc.WithEndpoint("ncacn_np:["+pipe+"]"),
		dcerpc.WithTimeout(3*time.Second),
		dcerpc.WithSMBPort(445),
	)
	if err != nil {
		cancel()
		return nil, err
	}

	defer func() {
		_ = conn.Close(secCtx)
	}()
	defer cancel()

	info, err := fn(secCtx, conn)
	if err != nil {
		return nil, err
	}
	info.Source = source
	if info.ComputerName == "" && info.Domain == "" {
		return nil, errors.New("empty SMB info")
	}
	return &info, nil
}

func fetchWKSSVCInfo(ctx context.Context, conn dcerpc.Conn) (SMBInfo, error) {
	client, err := wkssvc.NewWkssvcClient(ctx, conn, dcerpc.WithInsecure())
	if err != nil {
		return SMBInfo{}, err
	}

	resp, err := client.GetInfo(ctx, &wkssvc.GetInfoRequest{Level: 100})
	if err != nil {
		return SMBInfo{}, err
	}
	if resp.WorkstationInfo == nil {
		return SMBInfo{}, errors.New("wkssvc: missing workstation info")
	}
	data, ok := resp.WorkstationInfo.GetValue().(*wkssvc.WorkstationInfo100)
	if !ok || data == nil {
		return SMBInfo{}, errors.New("wkssvc: unexpected info type")
	}

	return SMBInfo{
		ComputerName: normaliseSMBValue(data.ComputerName),
		Domain:       normaliseSMBValue(data.LANGroup),
	}, nil
}

func fetchSRVSVCInfo(ctx context.Context, conn dcerpc.Conn) (SMBInfo, error) {
	client, err := srvsvc.NewSrvsvcClient(ctx, conn, dcerpc.WithInsecure())
	if err != nil {
		return SMBInfo{}, err
	}

	resp, err := client.GetInfo(ctx, &srvsvc.GetInfoRequest{Level: 100})
	if err != nil {
		return SMBInfo{}, err
	}
	if resp.Info == nil {
		return SMBInfo{}, errors.New("srvsvc: missing server info")
	}

	switch data := resp.Info.GetValue().(type) {
	case *dtyp.ServerInfo100:
		if data == nil {
			return SMBInfo{}, errors.New("srvsvc: empty server info")
		}
		return SMBInfo{ComputerName: normaliseSMBValue(data.Name)}, nil
	default:
		return SMBInfo{}, errors.New("srvsvc: unsupported info type")
	}
}

func normaliseSMBValue(value string) string {
	value = strings.Trim(value, "\x00")
	value = strings.TrimSpace(value)
	return value
}
