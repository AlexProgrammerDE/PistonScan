use std::net::Ipv4Addr;
use std::time::Duration;

use smb2::{
    ClientConfig, SmbClient,
    msg::{
        create::{
            CreateDisposition, CreateRequest, CreateResponse, ImpersonationLevel, ShareAccess,
        },
        ioctl::{FSCTL_PIPE_TRANSCEIVE, IoctlRequest, IoctlResponse, SMB2_0_IOCTL_IS_FSCTL},
    },
    pack::{ReadCursor, Unpack},
    rpc,
    types::{Command, FileId, OplockLevel, TreeId, flags::FileAccessMask, status::NtStatus},
};
use tokio::time::timeout;

use crate::snapshot::SmbInfo;

#[derive(Clone, Copy)]
pub(crate) enum Endpoint {
    Workstation,
    Server,
}

impl Endpoint {
    fn pipe(self) -> &'static str {
        match self {
            Self::Workstation => "wkssvc",
            Self::Server => "srvsvc",
        }
    }

    fn opnum(self) -> u16 {
        match self {
            Self::Workstation => 0,
            Self::Server => 21,
        }
    }

    fn bind(self) -> Vec<u8> {
        let mut pdu = rpc::build_srvsvc_bind(1);
        if matches!(self, Self::Workstation) {
            // Replace the abstract syntax with MS-WKST v1.0, leaving NDR32 intact.
            pdu[32..52].copy_from_slice(&[
                0x98, 0xd0, 0xff, 0x6b, 0x12, 0xa1, 0x10, 0x36, 0x98, 0x33, 0x46, 0xc3, 0xf8, 0x7e,
                0x34, 0x5a, 1, 0, 0, 0,
            ]);
        }
        pdu
    }
}

pub async fn discover(ip: Ipv4Addr) -> Option<SmbInfo> {
    timeout(Duration::from_secs(4), query(ip)).await.ok()?
}

async fn query(ip: Ipv4Addr) -> Option<SmbInfo> {
    let config = ClientConfig {
        addr: format!("{ip}:445"),
        dfs_enabled: false,
        ..ClientConfig::default()
    };
    let mut client = SmbClient::connect(config).await.ok()?;
    let tree = client.connect_share("IPC$").await.ok()?;
    let mut found = None;
    for endpoint in [Endpoint::Workstation, Endpoint::Server] {
        if let Some(file) = open(&client, tree.tree_id, endpoint).await {
            found = call(&client, tree.tree_id, file, endpoint).await;
            let _close = tree.close_handle(client.connection_mut(), file).await;
            if found.is_some() {
                break;
            }
        }
    }
    let _disconnect = client.disconnect_share(&tree).await;
    found
}

async fn open(client: &SmbClient, tree: TreeId, endpoint: Endpoint) -> Option<FileId> {
    let request = CreateRequest {
        requested_oplock_level: OplockLevel::None,
        impersonation_level: ImpersonationLevel::Impersonation,
        desired_access: FileAccessMask::new(
            FileAccessMask::FILE_READ_DATA | FileAccessMask::FILE_WRITE_DATA,
        ),
        file_attributes: 0,
        share_access: ShareAccess(ShareAccess::FILE_SHARE_READ | ShareAccess::FILE_SHARE_WRITE),
        create_disposition: CreateDisposition::FileOpen,
        create_options: 0,
        name: endpoint.pipe().to_owned(),
        create_contexts: Vec::new(),
    };
    let frame = client
        .connection()
        .execute(Command::Create, &request, Some(tree))
        .await
        .ok()?;
    if frame.header.status != NtStatus::SUCCESS {
        return None;
    }
    Some(
        CreateResponse::unpack(&mut ReadCursor::new(&frame.body))
            .ok()?
            .file_id,
    )
}

async fn call(
    client: &SmbClient,
    tree: TreeId,
    file: FileId,
    endpoint: Endpoint,
) -> Option<SmbInfo> {
    let bind = transact(client, tree, file, endpoint.bind()).await?;
    if bind.get(12..16)? != 1_u32.to_le_bytes() {
        return None;
    }
    rpc::parse_bind_ack(&bind).ok()?;
    // Both level-100 operations take a null server handle and the information level.
    let request = rpc::build_request(2, endpoint.opnum(), &[0, 0, 0, 0, 100, 0, 0, 0]);
    let response = transact(client, tree, file, request).await?;
    parse_reply(&response, endpoint)
}

/// Decodes the level-100 RPC response PDU for call ID 2.
pub(crate) fn parse_reply(response: &[u8], endpoint: Endpoint) -> Option<SmbInfo> {
    if response.get(12..16)? != 2_u32.to_le_bytes() {
        return None;
    }
    parse(rpc::parse_response(response).ok()?, endpoint)
}

async fn transact(
    client: &SmbClient,
    tree: TreeId,
    file: FileId,
    input_data: Vec<u8>,
) -> Option<Vec<u8>> {
    let request = IoctlRequest {
        ctl_code: FSCTL_PIPE_TRANSCEIVE,
        file_id: file,
        max_input_response: 0,
        max_output_response: 4096,
        flags: SMB2_0_IOCTL_IS_FSCTL,
        input_data,
    };
    let frame = client
        .connection()
        .execute(Command::Ioctl, &request, Some(tree))
        .await
        .ok()?;
    if frame.header.status != NtStatus::SUCCESS {
        return None;
    }
    let reply = IoctlResponse::unpack(&mut ReadCursor::new(&frame.body)).ok()?;
    (reply.ctl_code == request.ctl_code && reply.file_id == file).then_some(reply.output_data)
}

fn read_u32(data: &[u8], cursor: &mut usize) -> Option<u32> {
    let raw: [u8; 4] = data.get(*cursor..*cursor + 4)?.try_into().ok()?;
    *cursor += 4;
    Some(u32::from_le_bytes(raw))
}

fn read_string(data: &[u8], cursor: &mut usize) -> Option<String> {
    let maximum = read_u32(data, cursor)?;
    let offset = read_u32(data, cursor)?;
    let length = read_u32(data, cursor)?;
    if offset != 0 || length == 0 || length > maximum {
        return None;
    }
    let byte_length = usize::try_from(length).ok()?.checked_mul(2)?;
    let bytes = data.get(*cursor..cursor.checked_add(byte_length)?)?;
    let chars = bytes
        .as_chunks::<2>()
        .0
        .iter()
        .copied()
        .map(u16::from_le_bytes)
        .collect::<Vec<_>>();
    if chars.last() != Some(&0) {
        return None;
    }
    *cursor = (*cursor + byte_length).next_multiple_of(4);
    Some(
        String::from_utf16(&chars[..chars.len() - 1])
            .ok()?
            .trim()
            .to_owned(),
    )
}

fn parse(data: &[u8], endpoint: Endpoint) -> Option<SmbInfo> {
    let mut cursor = 0;
    if read_u32(data, &mut cursor)? != 100 || read_u32(data, &mut cursor)? == 0 {
        return None;
    }
    let _platform = read_u32(data, &mut cursor)?;
    let name_ref = read_u32(data, &mut cursor)?;
    let domain_ref = match endpoint {
        Endpoint::Workstation => {
            let domain_ref = read_u32(data, &mut cursor)?;
            cursor += 8; // Major and minor version.
            domain_ref
        }
        Endpoint::Server => 0,
    };
    let computer_name = if name_ref == 0 {
        String::new()
    } else {
        read_string(data, &mut cursor)?
    };
    let domain = if domain_ref == 0 {
        String::new()
    } else {
        read_string(data, &mut cursor)?
    };
    if read_u32(data, &mut cursor)? != 0 || (computer_name.is_empty() && domain.is_empty()) {
        return None;
    }
    Some(SmbInfo {
        computer_name,
        domain,
        source: endpoint.pipe().to_owned(),
    })
}

#[cfg(test)]
mod tests {
    use super::{Endpoint, parse};

    #[test]
    fn parses_level_100_workstation() {
        let mut response = [100_u32, 1, 500, 2, 3, 10, 0]
            .into_iter()
            .flat_map(u32::to_le_bytes)
            .collect::<Vec<_>>();
        for name in ["PC", "LAN"] {
            let chars = name.encode_utf16().chain([0]).collect::<Vec<_>>();
            let length = u32::try_from(chars.len()).unwrap_or_default();
            response.extend([length, 0, length].into_iter().flat_map(u32::to_le_bytes));
            response.extend(chars.into_iter().flat_map(u16::to_le_bytes));
            response.resize(response.len().next_multiple_of(4), 0);
        }
        response.extend_from_slice(&0_u32.to_le_bytes());
        let reply = parse(&response, Endpoint::Workstation);
        assert_eq!(
            reply.as_ref().map(|info| info.computer_name.as_str()),
            Some("PC"),
            "Computer name"
        );
        assert_eq!(
            reply.as_ref().map(|info| info.domain.as_str()),
            Some("LAN"),
            "Domain name"
        );
        assert!(
            parse(&response[..response.len() - 1], Endpoint::Workstation).is_none(),
            "Require the operation status"
        );
    }
}
