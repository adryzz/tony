use std::{net::{IpAddr, Ipv4Addr}, str::FromStr};

use chrono::{NaiveDateTime, NaiveDate, NaiveTime};

#[derive(Debug, Clone, Copy)]
pub struct LogMessage<'a> {
    pub server_ip: IpAddr,
    pub server_port: u16,
    pub user_ip: IpAddr,
    pub date_time: NaiveDateTime,
    pub http_method: &'a str,
    pub path: &'a str,
    pub version: &'a str,
    pub status_code: u16,
    pub response_length: u32,
    //pub response_time: u32,
    pub referer: Option<&'a str>,
    pub user_agent: Option<&'a str>,
}

#[derive(Debug, Clone)]
pub struct OwnedLogMessage {
    pub server_ip: IpAddr,
    pub server_port: u16,
    pub user_ip: IpAddr,
    pub date_time: NaiveDateTime,
    pub http_method: String,
    pub path: String,
    pub version: String,
    pub status_code: u16,
    pub response_length: u32,
    //pub response_time: u32,
    pub referer: Option<String>,
    pub user_agent: Option<String>,
}

impl<'a> LogMessage<'a> {
    pub fn to_owned(&self) -> OwnedLogMessage {
        OwnedLogMessage {
            server_ip: self.server_ip,
            server_port: self.server_port,
            user_ip: self.user_ip,
            date_time: self.date_time,
            http_method: self.http_method.to_owned(),
            path: self.path.to_owned(),
            version: self.version.to_owned(),
            status_code: self.status_code,
            response_length: self.response_length,
            //response_time: self.response_time,
            referer: self.referer.map(|r| r.to_owned()),
            user_agent: self.user_agent.map(|r| r.to_owned()),
        }
    }

    // log-format %si\ %sp\ %ci\ [%t]\ "%r"\ %ST\ %B\ "%hr"
    pub fn try_parse(source: &'a str) -> Option<LogMessage<'a>> {
        // parse server ip address
        // longest IPv6 is 45 characters, no need to look farther
        if source.len() < 100 {
            return None;
        }

        let mut str = source;

        // find the start of the actual log: "]:"
        let maxstart = split_max(str, 45);
        let startendindex = maxstart.find("]: ")?;
        str = &str[startendindex+3..];

        let cutmaxaddr = split_max(str, 45);

        let address = if !cutmaxaddr.starts_with('-') {
            let endaddrindex = cutmaxaddr.find(' ')?;
            let address = &str[..endaddrindex];
            str = &str[endaddrindex + 1..];
    
            IpAddr::from_str(address).ok()?
        } else {
            str = &str[2..];
            IpAddr::V4(Ipv4Addr::LOCALHOST)
        };

        // find the port, max 5 chars
        let cutmaxport = split_max(str, 5);
        let port = if !cutmaxport.starts_with('-') {
            let endportindex = cutmaxport.find(' ')?;
            let port = &str[..endportindex];
    
            str = &str[endportindex + 1..];
            u16::from_str(port).ok()?
        } else {
            str = &str[2..];
            0
        };

        // find the source address

        let cutmaxsrcaddr = split_max(str, 45);
        let endsrcaddrindex = cutmaxsrcaddr.find(' ')?;
        let srcaddress = &str[..endsrcaddrindex];

        let srcaddress = IpAddr::from_str(srcaddress).ok()?;

        str = &str[endsrcaddrindex + 1..];

        // find the date/time, max 30 chars

        let cutmaxdate = split_max(str, 30);
        let enddateindex = cutmaxdate.find(' ')?;
        let date = &str[..enddateindex];

        if date.len() < 8 {
            return None;
        }
        let split = parse_date_split(&date[1..date.len()-1])?;

        let datetime = NaiveDateTime::new(
            NaiveDate::from_ymd_opt(split[2] as i32, split[1], split[0])?,
            NaiveTime::from_hms_milli_opt(split[3], split[4], split[5], split[6])?,
        );

        str = &str[enddateindex + 1..];

        // find http method, max 7 chars

        let cutmaxmethod = split_max(str, 7);
        let endmethodindex = cutmaxmethod.find(' ')?;
        let method = &str[..endmethodindex];

        str = &str[endmethodindex + 1..];

        // find path, any length, capped at 300 chars, may be changed
        let cutmaxpath = split_max(str, 300);

        // find the start of the query parameters (if any) and split there
        let path = if let Some(idx) = cutmaxpath.find('?') {
            let path = &str[..idx];
            str = &str[idx + 1..];

            // if query parameters take more than 400 chars then fail ig
            let cutmaxquery = split_max(str, 400);
            let endqueryindex = cutmaxquery.find(' ')?;
            str = &str[endqueryindex + 1..];
            path
        } else {
            let endpathindex = cutmaxpath.find(' ')?;
            let path = &str[..endpathindex];
            str = &str[endpathindex + 1..];

            path
        };

        // find HTTP version, max 9 chars
        let cutmaxver = split_max(str, 9);
        let endverindex = cutmaxver.find(' ')?;
        let ver = &str[..endverindex];

        str = &str[endverindex + 1..];

        // find HTTP version, max 4 chars
        let cutmaxcode = split_max(str, 4);
        let endcodeindex = cutmaxcode.find(' ')?;
        let code = &str[..endcodeindex];

        let code = u16::from_str(code).ok()?;

        str = &str[endcodeindex + 1..];

        // find response length, max 10 chars
        let cutmaxlen = split_max(str, 10);
        let endlenindex = cutmaxlen.find(' ')?;
        let len = &str[..endlenindex];

        let len = u32::from_str(len).ok()?;

        str = &str[endlenindex + 1..];

        // find response time, max 10 chars
        /*let cutmaxtime = split_max(str, 10);
        let endtimeindex = cutmaxtime.find(' ')?;
        let time = &str[..endtimeindex];
        
        let time = u32::from_str(time).ok()?;
        
        str = &str[endtimeindex + 1..];*/

        // the rest is the list of headers

        // remove braces, split it in 2 where the '|' is, and if length is zero set it as None

        let mut referer = None;
        let mut user_agent = None;
        if str.len() > 3 {
            str = &str[1..str.len()-2];
            let separator_index = str.find('|')?;
            let left = &str[..separator_index];
            let right = &str[separator_index+1..];

            if left.len() > 0 {
                referer = Some(left);
            }

            if right.len() > 0 {
                user_agent = Some(right);
            }
        }
        Some(LogMessage {
            server_ip: address,
            server_port: port,
            user_ip: srcaddress,
            date_time: datetime,
            http_method: method,
            path: path,
            version: ver,
            status_code: code,
            response_length: len,
            //response_time: time,
            referer,
            user_agent,
        })
    }
}

fn split_max<'a>(src: &'a str, max: usize) -> &'a str {
    &src[..std::cmp::min(max, src.len())]
}

// splits date
fn parse_date_split(date: &str) -> Option<[u32; 7]> {
    // 07/Dec/2023:18:08:04.789
    // first 2 chars are day
    let daystr = &date[..2];
    let day = u32::from_str(daystr).ok()?;
    
    let date = &date[3..];

    // first 3 chars are month in text format
    let month = match &date[..3] {
        "Jan" => 1,
        "Feb" => 2,
        "Mar" => 3,
        "Apr" => 4,
        "May" => 5,
        "Jun" => 6,
        "Jul" => 7,
        "Aug" => 8,
        "Sep" => 9,
        "Oct" => 10,
        "Nov" => 11,
        "Dec" => 12,
        _ => return None
    };

    let date = &date[4..];
    // next up it's the year, and it ends at the first colon
    let maxc = split_max(date, 6);
    let yidx = maxc.find(':')?;
    let yearstr = &date[..yidx];
    let year = u32::from_str(yearstr).ok()?;

    let date = &date[yidx+1..];
    // then hour, minute, seconds and ms are simple

    let hstr = &date[..2];
    let hour = u32::from_str(hstr).ok()?;

    let date = &date[3..];

    let mstr = &date[..2];
    let min = u32::from_str(mstr).ok()?;

    let date = &date[3..];

    let sstr = &date[..2];
    let sec = u32::from_str(sstr).ok()?;

    let date = &date[3..];

    let ms = u32::from_str(date).ok()?;

    Some([day, month, year, hour, min, sec, ms])
}
